def flatten_errors(errors_dict):
    """Flattens DRF serializer error messages from list to string."""
    return {
        key: value[0] if isinstance(value, list) and value else value
        for key, value in errors_dict.items()
    }
