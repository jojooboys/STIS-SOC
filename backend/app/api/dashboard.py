"""Hitung agregat alert dan blokir untuk ringkasan serta grafik dashboard."""

from flask_restx import Namespace, Resource
from flask_login import login_required
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
from app.extensions import db
from app.models import Alert, BlockedIP

dashboard_ns = Namespace('dashboard', description='Dashboard Statistics')

@dashboard_ns.route('/stats')
class DashboardStats(Resource):
    method_decorators = [login_required]

    def get(self):
        """Get general dashboard statistics"""
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

        total_alerts = Alert.query.count()
        alerts_today = Alert.query.filter(Alert.fetched_at >= today).count()

        blocked_ips = BlockedIP.query.count()
        active_blocks = BlockedIP.query.filter_by(status='blocked').count()

        critical_alerts = Alert.query.filter(Alert.rule_level >= 12).count()
        high_alerts = Alert.query.filter(Alert.rule_level >= 10, Alert.rule_level < 12).count()
        medium_alerts = Alert.query.filter(Alert.rule_level >= 7, Alert.rule_level < 10).count()
        low_alerts = Alert.query.filter(Alert.rule_level < 7).count()

        return {
            "total_alerts": total_alerts,
            "alerts_today": alerts_today,
            "blocked_ips": blocked_ips,
            "active_blocks": active_blocks,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "medium_alerts": medium_alerts,
            "low_alerts": low_alerts
        }, 200

@dashboard_ns.route('/timeline')
class DashboardTimeline(Resource):
    method_decorators = [login_required]

    def get(self):
        """Get alert counts grouped by hour for the last 24 hours"""
        yesterday = datetime.now(timezone.utc) - timedelta(hours=24)

        if db.engine.name == 'sqlite':
            hour_func = func.strftime('%Y-%m-%dT%H:00:00', Alert.fetched_at)
        else:
            hour_func = func.date_trunc('hour', Alert.fetched_at)

        results = db.session.query(
            hour_func.label('hour'),
            func.count().label('count')
        ).filter(Alert.fetched_at >= yesterday)\
         .group_by('hour')\
         .order_by('hour').all()

        timeline = [{"hour": r.hour if isinstance(r.hour, str) else r.hour.isoformat(), "count": r.count} for r in results]
        return timeline, 200

@dashboard_ns.route('/top-sources')
class TopSources(Resource):
    method_decorators = [login_required]

    def get(self):
        """Get top 10 source IPs by alert count"""
        results = db.session.query(
            Alert.src_ip,
            func.count().label('count'),
            func.max(Alert.rule_level).label('max_level')
        ).filter(Alert.src_ip != None, Alert.src_ip != '')\
         .group_by(Alert.src_ip)\
         .order_by(func.count().desc())\
         .limit(10).all()

        top_sources = [{"ip": r.src_ip, "count": r.count, "max_level": r.max_level} for r in results]
        return top_sources, 200

@dashboard_ns.route('/severity-distribution')
class SeverityDistribution(Resource):
    method_decorators = [login_required]

    def get(self):
        """Get alert counts by severity category"""
        critical_alerts = Alert.query.filter(Alert.rule_level >= 12).count()
        high_alerts = Alert.query.filter(Alert.rule_level >= 10, Alert.rule_level < 12).count()
        medium_alerts = Alert.query.filter(Alert.rule_level >= 7, Alert.rule_level < 10).count()
        low_alerts = Alert.query.filter(Alert.rule_level < 7).count()

        return [
            {"name": "Critical", "value": critical_alerts, "color": "#ef4444"},
            {"name": "High", "value": high_alerts, "color": "#f97316"},
            {"name": "Medium", "value": medium_alerts, "color": "#eab308"},
            {"name": "Low", "value": low_alerts, "color": "#3b82f6"}
        ], 200
