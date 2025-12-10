import traceback
import os


def format_error_log(error: Exception, email=None):
    tb = traceback.extract_tb(error.__traceback__)[-1] 
    file_name = os.path.basename(tb.filename)

    log_table = f"""
┌────────────────────────── ERROR LOG ──────────────────────────┐
│ Module        : {file_name}
│ File          : {tb.filename}
│ Line          : {tb.lineno}
│ Function      : {tb.name}
│ Error Type    : {type(error).__name__}
│ Error Message : {str(error)}
│ User Email    : {email}
└────────────────────────────────────────────────────────────────┘
"""
    return log_table