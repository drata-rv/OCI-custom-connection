"""Transformation pipeline (spec section 7): raw OCI SDK objects -> allowlisted
source facts (normalize) -> OCID-resolved relationships (relationships) ->
derived facts (exposure, database_posture, vpn_posture) -> assertions
(findings) -> exactly one aggregate record (aggregate).
"""
