from flask import Blueprint, request, jsonify
from app.models import User, Dashboard
from app import db
import logging

dashboard_api = Blueprint('dashboard_api', __name__)

# ---------------------------
# 1) FETCH (READ)
# ---------------------------
@dashboard_api.route('/user_dashboards/<int:user_id>', methods=['GET'])
def get_user_dashboards(user_id):
    """
    Fetch all dashboard IDs assigned to the specified user.
    """
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # user.dashboard_id might be None or an empty list
        dashboard_id = user.dashboard_id if user.dashboard_id else []
        
        # Optional: If you want to return full dashboard details
        dashboards = Dashboard.query.filter(Dashboard.id.in_(dashboard_id)).order_by(Dashboard.name.asc()).all()
        dashboard_list = [{
            'id': dash.id,
            'name': dash.name,
            'image': dash.image,
            'dashboard_url': dash.dashboard_url,
            'layout': dash.layout
        } for dash in dashboards]

        return jsonify({
            'user_id': user.id,
            # 'dashboard_id': dashboard_id,
            'dashboards': dashboard_list
        }), 200

    except Exception as e:
        logging.error(f"Error fetching user dashboards: {str(e)}", exc_info=True)
        return jsonify({'error': 'An error occurred fetching user dashboards'}), 500


# ---------------------------
# 2) REPLACE (PUT)
# ---------------------------
# @dashboard_api.route('/user_dashboards', methods=['PUT'])
# def replace_user_dashboards():
#     """
#     Replace the entire dashboard_id array for a given user.
#     JSON body example:
#     {
#       "user_id": 17,
#       "dashboard_id": [1, 3]
#     }
#     """
#     try:
#         data = request.json
#         user_id = data.get('user_id')
#         new_dashboard_id = data.get('dashboard_id')

#         if not user_id or new_dashboard_id is None:
#             return jsonify({'error': 'user_id and dashboard_id are required'}), 400

#         if not isinstance(new_dashboard_id, list):
#             return jsonify({'error': 'dashboard_id must be a list'}), 400

#         user = User.query.get(user_id)
#         if not user:
#             return jsonify({'error': 'User not found'}), 404

#         # Optional: Validate that each ID actually exists in the Dashboard table
#         valid_dashboards = Dashboard.query.filter(Dashboard.id.in_(new_dashboard_id)).all()
#         valid_ids = [dash.id for dash in valid_dashboards]

#         # Replace the array with valid IDs
#         user.dashboard_id = valid_ids
#         db.session.commit()

#         return jsonify({
#             'message': 'User dashboards replaced successfully',
#             'dashboard_id': valid_ids
#         }), 200

#     except Exception as e:
#         logging.error(f"Error replacing user dashboards: {str(e)}", exc_info=True)
#         return jsonify({'error': 'An error occurred while replacing user dashboards'}), 500


# ---------------------------
# 3) ADD (PATCH)
# ---------------------------
@dashboard_api.route('/user_dashboards', methods=['PATCH'])
def add_user_dashboards():
    """
    Add new dashboard IDs to the user's existing list.
    JSON body example:
    {
      "user_id": 17,
      "dashboard_id": [2, 5]
    }
    """
    try:
        data = request.json
        user_id = data.get('user_id')
        new_ids = data.get('dashboard_id')

        if not user_id or not new_ids:
            return jsonify({'error': 'user_id and dashboard_id are required'}), 400

        if not isinstance(new_ids, list):
            return jsonify({'error': 'dashboard_id must be a list'}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Validate each new ID
        valid_dashboards = Dashboard.query.filter(Dashboard.id.in_(new_ids)).all()
        valid_ids = [dash.id for dash in valid_dashboards]

        # Merge existing IDs with new IDs
        existing_ids = user.dashboard_id if user.dashboard_id else []
        # Use a set to avoid duplicates, then convert back to list
        merged_ids = list(set(existing_ids + valid_ids))

        user.dashboard_id = merged_ids
        db.session.commit()

        return jsonify({
            'message': 'User dashboards updated (added) successfully',
            'dashboard_id': merged_ids
        }), 200

    except Exception as e:
        logging.error(f"Error adding user dashboards: {str(e)}", exc_info=True)
        return jsonify({'error': 'An error occurred while adding user dashboards'}), 500


# ---------------------------
# 4) REMOVE (DELETE)
# ---------------------------
@dashboard_api.route('/user_dashboards', methods=['DELETE'])
def remove_user_dashboards():
    """
    Remove specific dashboard IDs from the user's existing list.
    JSON body example:
    {
      "user_id": 17,
      "dashboard_id": [1]
    }
    """
    try:
        data = request.json
        user_id = data.get('user_id')
        remove_ids = data.get('dashboard_id')

        if not user_id or not remove_ids:
            return jsonify({'error': 'user_id and dashboard_id are required'}), 400

        if not isinstance(remove_ids, list):
            return jsonify({'error': 'dashboard_id must be a list'}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        existing_ids = user.dashboard_id if user.dashboard_id else []

        # Filter out any IDs that appear in remove_ids
        updated_ids = [d_id for d_id in existing_ids if d_id not in remove_ids]

        user.dashboard_id = updated_ids
        db.session.commit()

        return jsonify({
            'message': 'User dashboards removed successfully',
            'dashboard_id': updated_ids
        }), 200

    except Exception as e:
        logging.error(f"Error removing user dashboards: {str(e)}", exc_info=True)
        return jsonify({'error': 'An error occurred while removing user dashboards'}), 500
