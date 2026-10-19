"""Daftarkan namespace REST dan respons kesalahan yang konsisten untuk frontend."""

from flask import Blueprint, jsonify
from flask_restx import Api

from .auth import auth_ns
from .dashboard import dashboard_ns
from .alerts import alerts_ns
from .blocked_ips import blocked_ips_ns
from .audit import audit_ns
from .settings import settings_ns
from .assets import assets_ns

api_bp = Blueprint('api', __name__, url_prefix='/api')
api = Api(
    api_bp,
    title='STIS SOC API',
    version='1.0',
    description='Security Operation Center REST API',
    doc='/docs'
)

api.add_namespace(auth_ns)
api.add_namespace(dashboard_ns)
api.add_namespace(alerts_ns)
api.add_namespace(blocked_ips_ns)
api.add_namespace(audit_ns)
api.add_namespace(settings_ns)
api.add_namespace(assets_ns)

@api_bp.errorhandler(401)
def handle_401(error):
    return jsonify({"message": "Authentication required"}), 401

@api_bp.errorhandler(403)
def handle_403(error):
    return jsonify({"message": "Forbidden access"}), 403

@api_bp.errorhandler(404)
def handle_404(error):
    return jsonify({"message": "Resource not found"}), 404

@api_bp.errorhandler(500)
def handle_500(error):
    return jsonify({"message": "Internal server error"}), 500
