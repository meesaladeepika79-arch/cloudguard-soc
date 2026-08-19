"""
Cloud Resource Inventory Blueprint
Manages cloud resource listing and configuration inspection.
"""

from flask import Blueprint, render_template, jsonify, request
from routes.auth import login_required
from models.database_models import Resource

resources_bp = Blueprint('resources', __name__)

@resources_bp.route('/resources')
@login_required
def index():
    return render_template('resources.html')


@resources_bp.route('/api/resources')
@login_required
def get_resources():
    resource_type = request.args.get('type')
    status = request.args.get('status')
    
    query = Resource.query
    if resource_type and resource_type != 'ALL':
        query = query.filter_by(resource_type=resource_type)
    if status and status != 'ALL':
        query = query.filter_by(status=status)
        
    resources = query.order_by(Resource.resource_type.asc()).all()
    return jsonify([r.to_dict() for r in resources])
