#!
vault write keyfactor/roles/jdk allowed_domains=jdk.cms
vault write keyfactor/issue/jdk common_name=jd.jdk.cms
