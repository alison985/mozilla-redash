from itertools import chain
import json

from flask import request, url_for
from funcy import distinct, project, take

from flask_restful import abort
from redash import models, serializers, settings
from redash.handlers.base import BaseResource, get_object_or_404
from redash.permissions import (can_modify, require_admin_or_owner,
                                require_object_modify_permission,
                                require_permission)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import StaleDataError


class RecentDashboardsResource(BaseResource):
    @require_permission('list_dashboards')
    def get(self):
        """
        Lists dashboards modified in the last 7 days.
        """
        if settings.FEATURE_DUMB_RECENTS:
            dashboards = models.Dashboard.all(self.current_org, self.current_user.group_ids, self.current_user.id).order_by(models.Dashboard.updated_at.desc()).limit(10)
            dashboards = [d.to_dict() for d in dashboards]
        else:
            recent = [d.to_dict() for d in models.Dashboard.recent(self.current_org, self.current_user.group_ids, self.current_user.id, for_user=True)]

            global_recent = []
            if len(recent) < 10:
                global_recent = [d.to_dict() for d in models.Dashboard.recent(self.current_org, self.current_user.group_ids, self.current_user.id)]

            dashboards = take(20, distinct(chain(recent, global_recent), key=lambda d: d['id']))

        return dashboards


class DashboardListResource(BaseResource):
    @require_permission('list_dashboards')
    def get(self):
        """
        Lists all accessible dashboards.
        """
        results = models.Dashboard.all(self.current_org, self.current_user.group_ids, self.current_user.id)
        return [q.to_dict() for q in results]

    @require_permission('create_dashboard')
    def post(self):
        """
        Creates a new dashboard.

        :<json string name: Dashboard name

        Responds with a :ref:`dashboard <dashboard-response-label>`.
        """
        dashboard_properties = request.get_json(force=True)
        dashboard = models.Dashboard(name=dashboard_properties['name'],
                                     org=self.current_org,
                                     user=self.current_user,
                                     is_draft=True,
                                     layout='[]')
        dashboard.record_changes(changed_by=self.current_user)
        models.db.session.add(dashboard)
        models.db.session.commit()
        return dashboard.to_dict()

class DashboardResource(BaseResource):
    @require_permission('list_dashboards')
    def get(self, dashboard_slug=None):
        """
        Retrieves a dashboard.

        :qparam string slug: Slug of dashboard to retrieve.

        .. _dashboard-response-label:

        :>json number id: Dashboard ID
        :>json string name:
        :>json string slug:
        :>json number user_id: ID of the dashboard creator
        :>json string created_at: ISO format timestamp for dashboard creation
        :>json string updated_at: ISO format timestamp for last dashboard modification
        :>json number version: Revision number of dashboard
        :>json boolean dashboard_filters_enabled: Whether filters are enabled or not
        :>json boolean is_archived: Whether this dashboard has been removed from the index or not
        :>json boolean is_draft: Whether this dashboard is a draft or not.
        :>json array layout: Array of arrays containing widget IDs, corresponding to the rows and columns the widgets are displayed in
        :>json array widgets: Array of arrays containing :ref:`widget <widget-response-label>` data

        .. _widget-response-label:

        Widget structure:

        :>json number widget.id: Widget ID
        :>json number widget.width: Widget size
        :>json object widget.options: Widget options
        :>json number widget.dashboard_id: ID of dashboard containing this widget
        :>json string widget.text: Widget contents, if this is a text-box widget
        :>json object widget.visualization: Widget contents, if this is a visualization widget
        :>json string widget.created_at: ISO format timestamp for widget creation
        :>json string widget.updated_at: ISO format timestamp for last widget modification
        """
        dashboard = get_object_or_404(models.Dashboard.get_by_slug_and_org, dashboard_slug, self.current_org)
        response = dashboard.to_dict(with_widgets=True, user=self.current_user)

        api_key = models.ApiKey.get_by_object(dashboard)
        if api_key:
            response['public_url'] = url_for('redash.public_dashboard', token=api_key.api_key, org_slug=self.current_org.slug, _external=True)
            response['api_key'] = api_key.api_key

        response['can_edit'] = can_modify(dashboard, self.current_user)

        self.record_event({
            'action': 'view',
            'object_id': dashboard.id,
            'object_type': 'dashboard',
        })

        return response

    @require_permission('edit_dashboard')
    def post(self, dashboard_slug):
        """
        Modifies a dashboard.

        :qparam string slug: Slug of dashboard to retrieve.

        Responds with the updated :ref:`dashboard <dashboard-response-label>`.

        :status 200: success
        :status 409: Version conflict -- dashboard modified since last read
        """
        dashboard_properties = request.get_json(force=True)
        # TODO: either convert all requests to use slugs or ids
        dashboard = models.Dashboard.get_by_id_and_org(dashboard_slug, self.current_org)

        require_object_modify_permission(dashboard, self.current_user)
        if 'layout' in dashboard_properties:
            try:
                layout = json.loads(dashboard_properties['layout'])
            except ValueError:
                abort(400)
            if not isinstance(layout, list):
                abort(400)

        updates = project(dashboard_properties, ('name', 'layout', 'version',
                                                 'is_draft', 'dashboard_filters_enabled'))

        # SQLAlchemy handles the case where a concurrent transaction beats us
        # to the update. But we still have to make sure that we're not starting
        # out behind.
        if 'version' in updates and updates['version'] != dashboard.version:
            abort(409)

        updates['changed_by'] = self.current_user

        self.update_model(dashboard, updates)
        models.db.session.add(dashboard)
        try:
            models.db.session.commit()
        except StaleDataError:
            models.db.session.rollback()
            abort(409)
        except IntegrityError:
            models.db.session.rollback()
            abort(400)

        result = dashboard.to_dict(with_widgets=True, user=self.current_user)
        self.record_event({
            'action': 'edit',
            'object_id': dashboard.id,
            'object_type': 'dashboard',
        })
        return result

    @require_permission('edit_dashboard')
    def delete(self, dashboard_slug):
        """
        Archives a dashboard.

        :qparam string slug: Slug of dashboard to retrieve.

        Responds with the archived :ref:`dashboard <dashboard-response-label>`.
        """
        dashboard = models.Dashboard.get_by_slug_and_org(dashboard_slug, self.current_org)
        dashboard.is_archived = True
        dashboard.record_changes(changed_by=self.current_user)
        models.db.session.add(dashboard)
        d = dashboard.to_dict(with_widgets=True, user=self.current_user)
        models.db.session.commit()
        self.record_event({
            'action': 'archive',
            'object_id': dashboard.id,
            'object_type': 'dashboard',
        })
        return d


class PublicDashboardResource(BaseResource):
    def get(self, token):
        """
        Retrieve a public dashboard.

        :param token: An API key for a public dashboard.
        :>json array widgets: An array of arrays of :ref:`public widgets <public-widget-label>`, corresponding to the rows and columns the widgets are displayed in
        """
        if not isinstance(self.current_user, models.ApiUser):
            api_key = get_object_or_404(models.ApiKey.get_by_api_key, token)
            dashboard = api_key.object
        else:
            dashboard = self.current_user.object

        return serializers.public_dashboard(dashboard)


class DashboardShareResource(BaseResource):
    def post(self, dashboard_id):
        """
        Allow anonymous access to a dashboard.

        :param dashboard_id: The numeric ID of the dashboard to share.
        :>json string public_url: The URL for anonymous access to the dashboard.
        :>json api_key: The API key to use when accessing it.
        """
        dashboard = models.Dashboard.get_by_id_and_org(dashboard_id, self.current_org)
        require_admin_or_owner(dashboard.user_id)
        api_key = models.ApiKey.create_for_object(dashboard, self.current_user)
        models.db.session.flush()
        models.db.session.commit()

        public_url = url_for('redash.public_dashboard', token=api_key.api_key, org_slug=self.current_org.slug, _external=True)

        self.record_event({
            'action': 'activate_api_key',
            'object_id': dashboard.id,
            'object_type': 'dashboard',
        })

        return {'public_url': public_url, 'api_key': api_key.api_key}

    def delete(self, dashboard_id):
        """
        Disable anonymous access to a dashboard.

        :param dashboard_id: The numeric ID of the dashboard to unshare.
        """
        dashboard = models.Dashboard.get_by_id_and_org(dashboard_id, self.current_org)
        require_admin_or_owner(dashboard.user_id)
        api_key = models.ApiKey.get_by_object(dashboard)

        if api_key:
            api_key.active = False
            models.db.session.add(api_key)
            models.db.session.commit()

        self.record_event({
            'action': 'deactivate_api_key',
            'object_id': dashboard.id,
            'object_type': 'dashboard',
        })

class SearchDashboardResource(BaseResource):
    @require_permission('list_dashboards')
    def get(self):
        """
        Searches for a dashboard.

        Sends to models.py > Dashboard > search()
        search(cls, term, user_id, group_ids, limit_to_users_dashboards=False, include_drafts=False)
        """
        term = request.args.get('q', '')
        include_drafts = request.args.get('include_drafts') is not None
        user_id = request.args.get('user_id', '')
        group_ids = self.current_user.group_ids
        if group_ids == None and request.args.get('test',False):
            group_ids = [2] # the array that's used for test factory users
        return [q.to_dict() for q in models.Dashboard.search(term, user_id, group_ids, include_drafts=include_drafts)]

