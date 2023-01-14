CREATE TABLE bff_authorization_user_sessions (
    session_id varchar(100) NOT NULL,
    user_id int NOT NULL,
    resource varchar(100) NOT NULL,
    scopes varchar(1000) NOT NULL,
    access_token_value text DEFAULT NULL,
    refresh_token_value text DEFAULT NULL,
    PRIMARY KEY (session_id),
    FOREIGN KEY (user_id) REFERENCES "authorization".public.users(id),
    CONSTRAINT bff_authorization_user_sessions_ct_1 UNIQUE (user_id, resource, scopes)
);
