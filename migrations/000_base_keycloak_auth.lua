return {
    --支持数据库postgres和cassandra
    --当前数据库使用postgres，未定义cassandra创建方式
    postgres = {
        up = [[
            CREATE TABLE IF NOT EXISTS "keycloak_auth_tokens" (
                "id"                    UUID                         PRIMARY KEY,
                "tid"                   TEXT                         UNIQUE,
                "access_token"          TEXT                         UNIQUE,
                "refresh_token"         TEXT,
                "expires_in"            TEXT,
                "ttl"                   timestamptz(6)
            );

            CREATE TABLE IF NOT EXISTS "keycloak_auth_clients" (
                "id"                    UUID                         PRIMARY KEY,
                "client_uid"            TEXT                         UNIQUE,
                "client_id"             TEXT                         UNIQUE,
                "client_secret"         TEXT,
                "enabled"               BOOLEAN,
                "auth_enabled"          BOOLEAN,
                "client_resources"      TEXT,
                "ttl"                   timestamptz(6)
            );

            CREATE TABLE IF NOT EXISTS "keycloak_auth_user_permissions" (
                "id"                   UUID                         PRIMARY KEY,
                "user_client_id"       TEXT                         UNIQUE,
                "user_id"              TEXT,
                "client_id"            TEXT,
                "permissions"          TEXT,
                "ttl"                   timestamptz(6)
            );
        ]]
    },
    cassandra = {
        up = [[

        ]]
    },
}
