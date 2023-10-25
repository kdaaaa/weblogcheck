#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

// 自定义结构表示规则
struct Rule {
    std::vector<std::string> keywords;
    std::string ruleName;
};

// 函数返回规则向量
std::vector<Rule> getRules() {
    std::vector<Rule> rules;
    rules.push_back({ {"/plus/weixin.php", "signature"}, "74cms-sqli-1" });
    rules.push_back({ {"/plus/ajax_officebuilding.php", "key"}, "74cms-sqli-2" });
    rules.push_back({ {"/index.php", "company", "AjaxPersonal"}, "74cms-sqli" });
    rules.push_back({ {"/admin/test/index.jsp"}, "activemq-cve-2016-3088" });
    rules.push_back({ {"/api/v1/user/login"}, "alibaba-canal-default-password" });
    rules.push_back({ {"/api/v1/canal/config/1/1"}, "alibaba-canal-info-leak" });
    rules.push_back({ {"/nacos/v1/auth/users", "username", "password"}, "alibaba-nacos-v1-auth-bypass" });
    rules.push_back({ {"/nacos/v1/auth/users", "pageNo", "pageSize"}, "alibaba-nacos-v1-auth-bypass" });
    rules.push_back({ {"/nacos/v1/auth/users", "username"}, "alibaba-nacos-v1-auth-bypass" });
    rules.push_back({ {"/manager/radius/server_ping.php"}, "amtt-hiboss-server-ping-rce" });
    rules.push_back({ {"/api/v1/users/admin", "fields"}, "apache-ambari-default-password" });
    rules.push_back({ {"/druid/indexer/v1/sampler", "connect"}, "apache-druid-cve-2021-36749" });
    rules.push_back({ {"/jars/upload"}, "apache-flink-upload-rce" });
    rules.push_back({ {"/kylin/api/admin/config"}, "apache-kylin-unauth-cve-2020-13937" });
    rules.push_back({ {"/nifi-api/flow/current-user"}, "apache-nifi-api-unauthorized-access" });
    rules.push_back({ {"/webtools/control/xmlrpc"}, "apache-ofbiz-cve-2018-8033-xxe" });
    rules.push_back({ {"/api/v1/cluster/summary"}, "apache-storm-unauthorized-access" });
    rules.push_back({ {"/plug/oem/AspCms_OEMFun.asp"}, "aspcms-backend-leak" });
    rules.push_back({ {"/pma/"}, "bt742-pma-unauthorized-access" });
    rules.push_back({ {"/plugins/weathermap/editor.php", "mapname"}, "cacti-weathermap-file-write" });
    rules.push_back({ {"/plugins/weathermap/configs/test.php"}, "cacti-weathermap-file-write" });
    rules.push_back({ {"/cu.html"}, "chinaunicom-modem-default-password" });
    rules.push_back({ {"/+CSCOT+/oem-customization", "name"}, "cisco-cve-2020-3452-readfile" });
    rules.push_back({ {"/vpn/../vpns/cfg/smb.conf"}, "citrix-cve-2019-19781-path-traversal" });
    rules.push_back({ {"/menu/stapp"}, "citrix-cve-2020-8191-xss" });
    rules.push_back({ {"/pcidss/report", "loginchallengeresponse1requestbody"}, "citrix-cve-2020-8193-unauthorized" });
    rules.push_back({ {"/jsp/help-sb-download.jsp", "sbFileName"}, "citrix-xenmobile-cve-2020-8209" });
    rules.push_back({ {"/CFIDE/administrator/enter.cfm", "locale"}, "coldfusion-cve-2010-2861-lfi" });
    rules.push_back({ {"/spaces/viewdefaultdecorator.action", "decoratorName"}, "confluence-cve-2015-8399" });
    rules.push_back({ {"/rest/tinymce/1/macro/preview"}, "confluence-cve-2019-3396-lfi" });
    rules.push_back({ {"/pages/createpage-entervariables.action", "SpaceKey"}, "confluence-cve-2021-26084" });
    rules.push_back({ {"/WEB-INF/web.xml"}, "confluence-cve-2021-26085-arbitrary-file-read" });
    rules.push_back({ {"/v1/agent/self"}, "consul-rexec-rce" });
    rules.push_back({ {"/mailsms/s", "dumpConfig"}, "coremail-cnvd-2019-16798" });
    rules.push_back({ {"/includes/mysql2i/mysql2i.func.php"}, "couchcms-cve-2018-7662" });
    rules.push_back({ {"/addons/phpmailer/phpmailer.php"}, "couchcms-cve-2018-7662" });
    rules.push_back({ {"/_users/org.couchdb.user"}, "couchdb-cve-2017-12635" });
    rules.push_back({ {"/_config"}, "couchdb-unauth" });
    rules.push_back({ {"/actions/seomatic/meta-container/meta-link-container/"}, "craftcms-seomatic-cve-2020-9757-rce" });
    rules.push_back({ {"/actions/seomatic/meta-container/all-meta-containers"}, "craftcms-seomatic-cve-2020-9757-rce" });
    rules.push_back({ {"/RPC2_Login"}, "dahua-cve-2021-33044-authentication-bypass" });
    rules.push_back({ {"/login.cgi"}, "datang-ac-default-password-cnvd-2021-04128" });
    rules.push_back({ {"/plus/carbuyaction.php", "code"}, "dedecms-carbuyaction-fileinclude" });
    rules.push_back({ {"/include/downmix.inc.php"}, "dedecms-cve-2018-6910" });
    rules.push_back({ {"/tag_test_action.php", "partcode"}, "dedecms-cve-2018-7700-rce" });
    rules.push_back({ {"/plus/guestbook.php"}, "dedecms-guestbook-sqli" });
    rules.push_back({ {"/member/ajax_membergroup.php", "membergroup"}, "dedecms-membergroup-sqli" });
    rules.push_back({ {"/plus/download.php"}, "dedecms-url-redirection" });
    rules.push_back({ {"/forum.php"}, "discuz-ml3x-cnvd-2019-22239" });
    rules.push_back({ {"/faq.php", "gids"}, "discuz-v72-sqli" });
    rules.push_back({ {"/plugin.php", "wechat"}, "discuz-wechat-plugins-unauth" });
    rules.push_back({ {"/viewthread.php", "tid"}, "discuz-wooyun-2010-080723" });
    rules.push_back({ {"/hedwig.cgi"}, "dlink-850l-info-leak" });
    rules.push_back({ {"/apply_sec.cgi"}, "dlink-cve-2019-16920-rce" });
    rules.push_back({ {"/getcfg.php"}, "dlink-cve-2019-17506" });
    rules.push_back({ {"/config/getuser"}, "dlink-cve-2020-25078-account-disclosure" });
    rules.push_back({ {"/getcfg.php"}, "dlink-cve-2020-9376-dump-credentials" });
    rules.push_back({ {"/page/login/login.html"}, "dlink-dsl-2888a-rce" });
    rules.push_back({ {"/cgi-bin/execute_cmd.cgi"}, "dlink-dsl-2888a-rce" });
    rules.push_back({ {"/info"}, "docker-api-unauthorized-rce" });
    rules.push_back({ {"/v2/_catalog"}, "docker-registry-api-unauth" });
    rules.push_back({ {"/user/City_ajax.aspx"}, "dotnetcms-sqli" });
    rules.push_back({ {"/user/City_ajax.aspx", "CityId"}, "dotnetcms-sqli" });
    rules.push_back({ {"/cgi-bin/mainfunction.cgi"}, "draytek-cve-2020-8515" });
    rules.push_back({ {"/druid/index.html"}, "druid-monitor-unauth" });
    rules.push_back({ {"/node/", "hal_json"}, "drupal-cve-2019-6340" });
    rules.push_back({ {"/duomiphp/ajax.php", "uid"}, "duomicms-sqli" });
    rules.push_back({ {"/device.rsp"}, "dvr-cve-2018-9995" });
    rules.push_back({ {"/iclock/ccccc/windows/win.ini"}, "e-zkeco-cnvd-2020-57264-read-file" });
    rules.push_back({ {"/page/exportImport/uploadOperation.jsp"}, "ecology-arbitrary-file-upload" });
    rules.push_back({ {"/page/exportImport/fileTransfer/"}, "ecology-arbitrary-file-upload" });
    rules.push_back({ {"/weaver/ln.FileDownload", "fpath"}, "ecology-filedownload-directory-traversal" });
    rules.push_back({ {"/weaver/bsh.servlet.BshServlet"}, "ecology-javabeanshell-rce" });
    rules.push_back({ {"/weaver/org.springframework.web.servlet.ResourceServlet", "resource"}, "ecology-springframework-directory-traversal" });
    rules.push_back({ {"/mobile/plugin/SyncUserInfo.jsp?userIdentifiers=-1)union(select(3),null,null,null,null,null,str({{r1}}*{{r2}}),null", "userIdentifiers"}, "ecology-syncuserinfo-sqli" });
    rules.push_back({ {"/js/hrm/getdata.jsp", "sql"}, "ecology-v8-sqli" });
    rules.push_back({ {"/cpt/manage/validate.jsp"}, "ecology-validate-sqli" });
    rules.push_back({ {"/mobile/browser/WorkflowCenterTreeData.jsp"}, "ecology-workflowcentertreedata-sqli" });
    rules.push_back({ {"/delete_cart_goods.php"}, "ecshop-cnvd-2020-58823-sqli" });
    rules.push_back({ {"/user.php", "collection_list"}, "ecshop-collection-list-sqli" });
    rules.push_back({ {"/authenticationserverservlet"}, "eea-info-leak-cnvd-2021-10543" });
    rules.push_back({ {"/test/test1/123"}, "elasticsearch-cve-2014-3120" });
    rules.push_back({ {"/_search"}, "elasticsearch-cve-2014-3120" });
    rules.push_back({ {"/test/test"}, "elasticsearch-cve-2015-1427" });
    rules.push_back({ {"/_search"}, "elasticsearch-cve-2015-1427" });
    rules.push_back({ {"/_plugin/head/"}, "elasticsearch-cve-2015-3337-lfi" });
    rules.push_back({ {"/_snapshot/"}, "elasticsearch-cve-2015-5531" });
    rules.push_back({ {"/_cat"}, "elasticsearch-unauth" });
    rules.push_back({ {"/v2/keys/"}, "etcd-unauth" });
    rules.push_back({ {"/v2/keys/", "quorum"}, "etcd-unauth" });
    rules.push_back({ {"/upload/mobile/index.php", "price_max"}, "etouch-v2-sqli" });
    rules.push_back({ {"/owa/auth/x.js"}, "exchange-cve-2021-26855-ssrf" });
    rules.push_back({ {"/autodiscover/autodiscover.json"}, "exchange-cve-2021-41349-xss" });
    rules.push_back({ {"/mgmt/tm/util/bash"}, "f5-cve-2021-22986" });
    rules.push_back({ {"/tmui/login.jsp/", "/tmui/locallb/workspace/fileRead.jsp"}, "f5-tmui-cve-2020-5902-rce" });
    rules.push_back({ {"/index.php", "id", "a=showcate"}, "fangweicms-sqli" });
    rules.push_back({ {"/index.php", "id", "Admin-Data-down"}, "feifeicms-lfr" });
    rules.push_back({ {"/index.php", "param", "sql"}, "finecms-sqli" });
    rules.push_back({ {"/report/ReportServer", "get_geo_json", "resourcepath"}, "finereport-directory-traversal" });
    rules.push_back({ {"/php/change_config.php"}, "flexpaper-cve-2018-11686" });
    rules.push_back({ {"/php/setup.php", "PDF2SWF_PATH"}, "flexpaper-cve-2018-11686" });
    rules.push_back({ {"/jobmanager/logs/"}, "flink-jobmanager-cve-2020-17519-lfi" });
    rules.push_back({ {"/api/proxy/tcp"}, "frp-dashboard-unauth" });
    rules.push_back({ {"/admin/sql", "query"}, "gilacms-cve-2020-5515" });
    rules.push_back({ {"/api/graphql"}, "gitlab-graphql-info-leak-cve-2020-26413" });
    rules.push_back({ {"/api/v4/ci/lint"}, "gitlab-ssrf-cve-2021-22214" });
    rules.push_back({ {"/tree/a/search"}, "gitlist-rce-cve-2018-1000533" });
    rules.push_back({ {"/theme/", "/META-INF/MANIFEST.MF"}, "glassfish-cve-2017-1000028-lfi" });
    rules.push_back({ {"/debug/pprof/"}, "go-pprof-leak" });
    rules.push_back({ {"/debug/pprof/goroutine"}, "go-pprof-leak" });
    rules.push_back({ {"/go/add-on/business-continuity/api/plugin", "pluginName"}, "gocd-cve-2021-43287" });
    rules.push_back({ {"/h2-console/"}, "h2-database-web-console-unauthorized-access" });
    rules.push_back({ {"/imc/javax.faces.resource/dynamiccontent.properties.xhtml"}, "h3c-imc-rce" });
    rules.push_back({ {"/audit/gui_detail_view.php", "uid"}, "h3c-secparh-any-user-login" });
    rules.push_back({ {"/api/v1/GetSrc"}, "h5s-video-platform-cnvd-2020-67113-unauth" });
    rules.push_back({ {"/api/v1/GetDevice"}, "h5s-video-platform-cnvd-2020-67113-unauth" });
    rules.push_back({ {"/ws/v1/cluster/info"}, "hadoop-yarn-unauth" });
    rules.push_back({ {"/register/toDownload.do", "fileName"}, "hanming-video-conferencing-file-read" });
    rules.push_back({ {"/api/users"}, "harbor-cve-2019-16097" });
    rules.push_back({ {"/system/deviceInfo"}, "hikvision-cve-2017-7921" });
    rules.push_back({ {"/config/user.xml"}, "hikvision-info-leak" });
    rules.push_back({ {"/authorize.action"}, "hikvision-intercom-service-default-password" });
    rules.push_back({ {"/SDK/webLanguage"}, "hikvision-unauthenticated-rce-cve-2021-36260" });
    rules.push_back({ {"/fileDownload", "action=downloadBackupFile"}, "hjtcloud-arbitrary-fileread" });
    rules.push_back({ {"/him/api/rest/V1.0/system/log/list", "filePath"}, "hjtcloud-directory-file-leak" });
    rules.push_back({ {"/index.htm", "PAGE=web"}, "ifw8-router-cve-2019-16313" });
    rules.push_back({ {"/action/usermanager.htm"}, "ifw8-router-cve-2019-16313" });
    rules.push_back({ {"/ping"}, "influxdb-unauth" });
    rules.push_back({ {"/query", "q", "show", "users"}, "influxdb-unauth" });
    rules.push_back({ {"/admin-console/index.seam", "actionOutcome"}, "jboss-cve-2010-1871" });
    rules.push_back({ {"/jmx-console/"}, "jboss-unauth" });
    rules.push_back({ {"/systemController/showOrDownByurl.do", "dbPath"}, "jeewms-showordownbyurl-fileread" });
    rules.push_back({ {"/Images/Remote", "imageUrl"}, "jellyfin-cve-2021-29490" });
    rules.push_back({ {"/Items/RemoteSearch/Image", "ImageUrl", "ProviderName"}, "jellyfin-cve-2021-29490" });
    rules.push_back({ {"/Audio/1/hls/"}, "jellyfin-file-read-cve-2021-21402" });
    rules.push_back({ {"/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.github.config.GitHubTokenCredentialsCreator/createTokenByPassword", "apiUrl"}, "jenkins-cve-2018-1000600" });
    rules.push_back({ {"/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile", "value"}, "jenkins-cve-2018-1000861-rce" });
    rules.push_back({ {"/script"}, "jenkins-unauthorized-access" });
    rules.push_back({ {"/%2e/WEB-INF/web.xml"}, "jetty-cve-2021-28164" });
    rules.push_back({ {"/c6/Jhsoft.Web.login/AjaxForLogin.aspx"}, "jinher-oa-c6-default-password" });
    rules.push_back({ {"/secure/ContactAdministrators!default.jspa"}, "jira-cve-2019-11581" });
    rules.push_back({ {"/secure/ContactAdministrators.jspa"}, "jira-cve-2019-11581" });
    rules.push_back({ {"/s/anything/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml"}, "jira-cve-2019-8442" });
    rules.push_back({ {"/rest/api/latest/groupuserpicker"}, "jira-cve-2019-8449" });
    rules.push_back({ {"/secure/QueryComponent!Default.jspa"}, "jira-cve-2020-14179" });
    rules.push_back({ {"/secure/ViewUserHover.jspa", "username"}, "jira-cve-2020-14181" });
    rules.push_back({ {"/plugins/servlet/gadgets/makeRequest?url={{originScheme}}://{{originHost}}@{{reverseHost}}{{reverseURL}}"}, "jira-ssrf-cve-2019-8451" });
    rules.push_back({ {"/index.php", "list[select]"}, "joomla-cve-2015-7297-sqli" });
    rules.push_back({ {"/index.php", "list[fullordering]"}, "joomla-cve-2017-8917-sqli" });
    rules.push_back({ {"/index.php", "sessionid"}, "joomla-cve-2018-7314-sql" });
    rules.push_back({ {"/api/v1/authentication/connection-token/"}, "jumpserver-unauth-rce" });
    rules.push_back({ {"/api/v1/authentication/connection-token/", "user-only"}, "jumpserver-unauth-rce" });
    rules.push_back({ {"/api/v1/users/connection-token/"}, "jumpserver-unauth-rce" });
    rules.push_back({ {"/api/v1/users/connection-token/", "user-only"}, "jumpserver-unauth-rce" });
    rules.push_back({ {"/terminals/3"}, "jupyter-notebook-unauthorized-access" });
    rules.push_back({ {"/api/console/api_server", "apis"}, "kibana-cve-2018-17246" });
    rules.push_back({ {"/app/kibana"}, "kibana-unauth" });
    rules.push_back({ {"/appmonitor/protected/selector/server_file/files", "folder"}, "kingdee-eas-directory-traversal" });
    rules.push_back({ {"/inter/ajax.php", "cmd=get_user_login_cmd"}, "kingsoft-v8-default-password" });
    rules.push_back({ {"/htmltopdf/downfile.php", "filename"}, "kingsoft-v8-file-read" });
    rules.push_back({ {"/status"}, "kong-cve-2020-11710-unauth" });
    rules.push_back({ {"/api/v1/nodes"}, "kubernetes-unauth" });
    rules.push_back({ {"/hosts"}, "kyan-network-monitoring-account-password-leakage" });
    rules.push_back({ {"/sys/ui/extend/varkind/custom.jsp"}, "landray-oa-custom-jsp-fileread" });
    rules.push_back({ {"/conf/config.properties"}, "lanproxy-cve-2021-3019-lfi" });
    rules.push_back({ {"/_ignition/execute-solution"}, "laravel-cve-2021-3129" });
    rules.push_back({ {"/storage/logs/laravel.log"}, "laravel-improper-webdir" });
    rules.push_back({ {"/index.php", "wd"}, "maccms-rce" });
    rules.push_back({ {"/extend/Qcloud/Sms/Sms.php"}, "maccmsv10-backdoor" });
    rules.push_back({ {"/admin/", "id", "union"}, "metinfo-cve-2019-16996-sqli" });
    rules.push_back({ {"/admin/", "appno"}, "metinfo-cve-2019-17418-sqli" });
    rules.push_back({ {"/include/thumb.php", "dir"}, "metinfo-file-read" });
    rules.push_back({ {"/minio/webrpc"}, "minio-default-password" });
    rules.push_back({ {"/checkValid"}, "mongo-express-cve-2019-10758" });
    rules.push_back({ {"/webui/", "file_name", "g=sys_dia_data_down"}, "mpsec-isg1000-file-read" });
    rules.push_back({ {"/images/lists", "cid"}, "msvod-sqli" });
    rules.push_back({ {"/index.php/bbs/index/download", "url"}, "myucms-lfr" });
    rules.push_back({ {"/nagiosql/admin/commandline.php", "cname"}, "nagio-cve-2018-10735" });
    rules.push_back({ {"/nagiosql/admin/info.php", "key1"}, "nagio-cve-2018-10736" });
    rules.push_back({ {"/nagiosql/admin/logbook.php"}, "nagio-cve-2018-10737" });
    rules.push_back({ {"/nagiosql/admin/menuaccess.php"}, "nagio-cve-2018-10738" });
    rules.push_back({ {"/user/login/checkPermit"}, "netentsec-icg-default-password" });
    rules.push_back({ {"/directdata/direct/router"}, "netentsec-ngfw-rce" });
    rules.push_back({ {"/passwordrecovered.cgi"}, "netgear-cve-2017-5521" });
    rules.push_back({ {"/_next/"}, "nextjs-cve-2017-16877" });
    rules.push_back({ {"/service/extdirect"}, "nexus-cve-2019-7238" });
    rules.push_back({ {"/rest/beta/repositories/go/group"}, "nexus-cve-2020-10199" });
    rules.push_back({ {"/extdirect"}, "nexus-cve-2020-10204" });
    rules.push_back({ {"/service/local/authentication/login"}, "nexus-default-password" });
    rules.push_back({ {"/ui_base/js/", "settings.js"}, "node-red-dashboard-file-read-cve-2021-3223" });
    rules.push_back({ {"/login/verify"}, "nps-default-password" });
    rules.push_back({ {"/admin/cert_download.php"}, "ns-asg-file-read" });
    rules.push_back({ {"/webapi/v1/system/accountmanage/account"}, "nsfocus-uts-password-leak" });
    rules.push_back({ {"/css_parser.php"}, "nuuo-file-inclusion" });
    rules.push_back({ {"/base_import/static/"}, "odoo-file-read" });
    rules.push_back({ {"/getFavicon"}, "openfire-cve-2019-18394-ssrf" });
    rules.push_back({ {"/s/opentsdb_header.jpg"}, "opentsdb-cve-2020-35476-rce" });
    rules.push_back({ {"/api/put"}, "opentsdb-cve-2020-35476-rce" });
    rules.push_back({ {"/q", "yrange"}, "opentsdb-cve-2020-35476-rce" });
    rules.push_back({ {"/login/userverify.cgi"}, "panabit-gateway-default-password" });
    rules.push_back({ {"/pandora_console/index.php"}, "pandorafms-cve-2019-20224-rce" });
    rules.push_back({ {"/data/pbootcms.db"}, "pbootcms-database-file-download" });
    rules.push_back({ {"/pentaho/api/userrolelist/systemRoles", "require-cfg.js"}, "pentaho-cve-2021-31602-authentication-bypass" });
    rules.push_back({ {"/api/userrolelist/systemRoles", "require-cfg.js"}, "pentaho-cve-2021-31602-authentication-bypass" });
    rules.push_back({ {"/type.php", "template"}, "phpcms-cve-2018-19127" });
    rules.push_back({ {"/data/cache_template/rss.tpl.php"}, "phpcms-cve-2018-19127" });
    rules.push_back({ {"/index.php", "db_sql.php", "target"}, "phpmyadmin-cve-2018-12613-file-inclusion" });
    rules.push_back({ {"/scripts/setup.php"}, "phpmyadmin-setup-deserialization" });
    rules.push_back({ {"/api.php", "sort"}, "phpok-sqli" });
    rules.push_back({ {"/include/plugin/payment/alipay/pay.php", "id"}, "phpshe-sqli" });
    rules.push_back({ {"/index.php/.php"}, "phpstudy-nginx-wrong-resolve" });
    rules.push_back({ {"/index.php/.xxx"}, "phpstudy-nginx-wrong-resolve" });
    rules.push_back({ {"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"}, "phpunit-cve-2017-9841-rce" });
    rules.push_back({ {"/upload/UploadResourcePic.ashx", "ResourceID"}, "powercreator-arbitrary-file-upload" });
    rules.push_back({ {"/new/newhttp"}, "prometheus-url-redirection-cve-2021-29622" });
    rules.push_back({ {"/html5acc/guacamole/", " /dana-na/"}, "pulse-cve-2019-11510" });
    rules.push_back({ {"/debug/pyspidervulntest/run"}, "pyspider-unauthorized-access" });
    rules.push_back({ {"/f/job.php", "pre"}, "qibocms-sqli" });
    rules.push_back({ {"/get_luser_by_sshport.php", "clientip"}, "qilin-bastion-host-rce" });
    rules.push_back({ {"/audit/gui_detail_view.php", "uid"}, "qizhi-fortressaircraft-unauthorized" });
    rules.push_back({ {"/photo/p/api/album.php"}, "qnap-cve-2019-7192" });
    rules.push_back({ {"/photo/slideshow.php"}, "qnap-cve-2019-7192" });
    rules.push_back({ {"/photo/p/api/video.php"}, "qnap-cve-2019-7192" });
    rules.push_back({ {"/api/whoami"}, "rabbitmq-default-password" });
    rules.push_back({ {"/assets/file"}, "rails-cve-2018-3760-rce" });
    rules.push_back({ {"/tests/generate.php"}, "razor-cve-2018-8770" });
    rules.push_back({ {"/install/lib/ajaxHandlers/ajaxServerSettingsChk.php", "rootUname"}, "rconfig-cve-2019-16663" });
    rules.push_back({ {"/resin-doc/resource/tutorial/jndi-appconfig/test", "inputFile"}, "resin-inputfile-fileread-or-ssrf" });
    rules.push_back({ {"/resin-doc/viewfile/", "file"}, "resin-viewfile-fileread" });
    rules.push_back({ {"/index.php", "action=login.index"}, "rockmongo-default-password" });
    rules.push_back({ {"/guest_auth/guestIsUp.php"}, "ruijie-eweb-rce-cnvd-2021-09650" });
    rules.push_back({ {"/WEB_VMS/LEVEL15/"}, "ruijie-nbr1300g-cli-password-leak" });
    rules.push_back({ {"/common/download/resource", "resource"}, "ruoyi-management-fileread" });
    rules.push_back({ {"/(download)/tmp/1.txt"}, "samsung-wea453e-rce" });
    rules.push_back({ {"/tool/log/c.php", "strip_slashes"}, "sangfor-ba-rce" });
    rules.push_back({ {"/api/edr/sangforinter/v2/cssp/slog_client"}, "sangfor-edr-cssp-rce" });
    rules.push_back({ {"/cgi-bin/libagent.cgi"}, "satellian-cve-2020-7980-rce" });
    rules.push_back({ {"/comment/api/index.php", "rlist[]"}, "seacms-before-v992-rce" });
    rules.push_back({ {"/data/mysqli_error_trace.php"}, "seacms-before-v992-rce" });
    rules.push_back({ {"/yyoa/DownExcelBeanServlet"}, "seeyon-a6-employee-info-leak" });
    rules.push_back({ {"/seeyon/", "/ajax.do"}, "seeyon-ajax-unauthorized-access" });
    rules.push_back({ {"/seeyon/", "ajax.do", "managerName=mMOneProfileManager", "managerMethod=getOAProfile"}, "seeyon-ajax-unauthorized-access" });
    rules.push_back({ {"/seeyon/webmail.do", "method=doDownloadAtt"}, "seeyon-cnvd-2020-62422-readfile" });
    rules.push_back({ {"/seeyon/thirdpartyController.do"}, "seeyon-oa-cookie-leak" });
    rules.push_back({ {"/yyoa/ext/https/getSessionList.jsp"}, "seeyon-session-leak" });
    rules.push_back({ {"/yyoa/ext/trafaxserver/downloadAtt.jsp", "attach_ids"}, "seeyon-wooyun-2015-0108235-sqli" });
    rules.push_back({ {"/NCFindWeb", "service=IPreAlertConfigService", "filename"}, "seeyon-wooyun-2015-148227" });
    rules.push_back({ {"/index.php", "goods_id"}, "shiziyu-cms-apicontroller-sqli" });
    rules.push_back({ {"/public/index.php", "/index/qrcode/download/url/"}, "shopxo-cnvd-2021-15822" });
    rules.push_back({ {"/server/index.php", "/api/user/login"}, "showdoc-default-password" });
    rules.push_back({ {"/index.php", "/home/page/uploadImg"}, "showdoc-uploadfile" });
    rules.push_back({ {"/Public/Uploads/"}, "showdoc-uploadfile" });
    rules.push_back({ {"/graphql"}, "skywalking-cve-2020-9483-sqli" });
    rules.push_back({ {"/web.config.i18n.ashx"}, "solarwinds-cve-2020-10148" });
    rules.push_back({ {"/solr/admin/cores"}, "solr-cve-2017-12629-xxe" });
    rules.push_back({ {"/solr/", "/select"}, "solr-cve-2017-12629-xxe" });
    rules.push_back({ {"/solr/", "/dataimport", "dataConfig"}, "solr-cve-2019-0193" });
    rules.push_back({ {"/solr/", "/dataimport"}, "solr-cve-2019-0193" });
    rules.push_back({ {"/solr/", "/config"}, "solr-fileread" });
    rules.push_back({ {"/solr/", "/debug/dump"}, "solr-fileread" });
    rules.push_back({ {"/api/settings/values"}, "sonarqube-cve-2020-27986-unauth" });
    rules.push_back({ {"/cgi-bin/jarrewrite.sh"}, "sonicwall-ssl-vpn-rce" });
    rules.push_back({ {"/v1/submissions"}, "spark-api-unauth" });
    rules.push_back({ {"/php/ping.php"}, "spon-ip-intercom-ping-rce" });
    rules.push_back({ {"/php/rj_get_token.php"}, "spon-ip-intercom-file-read" });
    rules.push_back({ {"/php/exportrecord.php", "downname"}, "spon-ip-intercom-file-read" });
    rules.push_back({ {"/php/getjson.php"}, "spon-ip-intercom-file-read" });
    rules.push_back({ {"/oauth/authorize", "response_type"}, "spring-cve-2016-4977" });
    rules.push_back({ {"/env"}, "springboot-env-unauth" });
    rules.push_back({ {"/actuator/env"}, "springboot-env-unauth" });
    rules.push_back({ {"/test/pathtraversal/master/"}, "springcloud-cve-2019-3799" });
    rules.push_back({ {"/RPC2"}, "supervisord-cve-2017-11610" });
    rules.push_back({ {"/api/ping", "host"}, "tamronos-iptv-rce" });
    rules.push_back({ {"/manager/index.php"}, "telecom-gateway-default-password" });
    rules.push_back({ {"/manager/login.php"}, "telecom-gateway-default-password" });
    rules.push_back({ {"/data/plugins_listing"}, "tensorboard-unauth" });
    rules.push_back({ {"/include/exportUser.php", "func"}, "terramaster-cve-2020-15568" });
    rules.push_back({ {"/include/makecvs.php", "Event"}, "terramaster-tos-rce-cve-2020-28188" });
    rules.push_back({ {"/admin.html", "admin/api.Update/get/encode/"}, "thinkadmin-v6-readfile" });
    rules.push_back({ {"templateFile"}, "thinkcmf-lfi" });
    rules.push_back({ {"/index.php", "content"}, "thinkcmf-write-shell" });
    rules.push_back({ {"/index.php", "function=call_user_func_array"}, "thinkphp5-controller-rce" });
    rules.push_back({ {"/api/dbstat/gettablessize"}, "tianqing-info-leak" });
    rules.push_back({ {"/jkstatus;"}, "tomcat-cve-2018-11759" });
    rules.push_back({ {"/jkstatus;", "cmd=dump"}, "tomcat-cve-2018-11759" });
    rules.push_back({ {"/general/calendar/arrange/get_cal_list.php"}, "tongda-meeting-unauthorized-access" });
    rules.push_back({ {"/mobile/auth_mobi.php"}, "tongda-user-session-disclosure" });
    rules.push_back({ {"/general/userinfo.php"}, "tongda-user-session-disclosure" });
    rules.push_back({ {"/index.php/Home/uploadify/fileList"}, "tpshop-directory-traversal" });
    rules.push_back({ {"/mobile/index/index2/id/"}, "tpshop-sqli" });
    rules.push_back({ {"/Pages/login.htm"}, "tvt-nvms-1000-file-read-cve-2019-20085" });
    rules.push_back({ {"/ueditor/net/controller.ashx"}, "ueditor-cnvd-2017-20077-file-upload" });
    rules.push_back({ {"/ajax/render/widget_tabbedcontainer_tab_panel"}, "vbulletin-cve-2019-16759-bypass" });
    rules.push_back({ {"/eam/vib", "id"}, "vmware-vcenter-arbitrary-file-read" });
    rules.push_back({ {"/wls-wsat/CoordinatorPortType"}, "weblogic-cve-2017-10271" });
    rules.push_back({ {"/ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.capability.VsanCapabilityProvider/getClusterCapabilityData"}, "vmware-vcenter-cve-2021-21985-rce" });
    rules.push_back({ {"/ui/h5-vsan/rest/proxy/service/vmodlContext/loadVmodlPackages"}, "vmware-vcenter-cve-2021-21985-rce" });
    rules.push_back({ {"/ui/h5-vsan/rest/proxy/service/systemProperties/getProperty"}, "vmware-vcenter-cve-2021-21985-rce" });
    rules.push_back({ {"/ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.capability.VsanCapabilityProvider/getClusterCapabilityData"}, "vmware-vcenter-cve-2021-21985-rce" });
    rules.push_back({ {"/ui/vropspluginui/rest/services/uploadova"}, "vmware-vcenter-unauthorized-rce-cve-2021-21972" });
    rules.push_back({ {"/ui/vropspluginui/rest/services/getstatus"}, "vmware-vcenter-unauthorized-rce-cve-2021-21972" });
    rules.push_back({ {"/casa/nodes/thumbprints"}, "vmware-vrealize-cve-2021-21975-ssrf" });
    rules.push_back({ {"/wxjsapi/saveYZJFile", "downloadUrl"}, "weaver-ebridge-file-read" });
    rules.push_back({ {"/file/fileNoLogin/"}, "weaver-ebridge-file-read" });
    rules.push_back({ {"/_async/AsyncResponseService"}, "weblogic-cve-2019-2729-2" });
    rules.push_back({ {"/_async/favicon.ico"}, "weblogic-cve-2019-2729-2" });
    rules.push_back({ {"/console/images/", "/console.portal"}, "weblogic-cve-2020-14750" });
    rules.push_back({ {"/uddiexplorer/SearchPublicRegistries.jsp"}, "weblogic-ssrf" });
    rules.push_back({ {"/password_change.cgi"}, "webmin-cve-2019-15107-rce" });
    rules.push_back({ {"/public/index.php/material/Material/_download_imgage", "picUrl"}, "weiphp-path-traversal" });
    rules.push_back({ {"/public/index.php/home/file/user_pics"}, "weiphp-path-traversal" });
    rules.push_back({ {"/public/uploads/picture/"}, "weiphp-path-traversal" });
    rules.push_back({ {"/public/index.php/home/index/bind_follow/", "uid[1]=)"}, "weiphp-sql" });
    rules.push_back({ {"/api/sms_check.php", "param"}, "wuzhicms-v410-sqli" });
    rules.push_back({ {"/wp-admin/admin.php", "download_report"}, "wordpress-cve-2019-19985-infoleak" });
    rules.push_back({ {"/wp-content/plugins/adaptive-images/adaptive-images-script.php", "adaptive-images-settings[source_file]"}, "wordpress-ext-adaptive-images-lfi" });
    rules.push_back({ {"/wp-content/plugins/mailpress/mp-includes/action.php"}, "wordpress-ext-mailpress-rce" });
    rules.push_back({ {"/backup/auto.php", "path"}, "xunchi-cnvd-2020-23735-file-read" });
    rules.push_back({ {"/api/user/reg"}, "yapi-rce" });
    rules.push_back({ {"/api/group/list"}, "yapi-rce" });
    rules.push_back({ {"/api/project/add"}, "yapi-rce" });
    rules.push_back({ {"/api/project/get"}, "yapi-rce" });
    rules.push_back({ {"/api/interface/add"}, "yapi-rce" });
    rules.push_back({ {"/api/plugin/advmock/save"}, "yapi-rce" });
    rules.push_back({ {"/api/project/del"}, "yapi-rce" });
    rules.push_back({ {"/servlet/~ic/bsh.servlet.BshServlet"}, "yonyou-nc-bsh-servlet-bshservlet-rce" });
    rules.push_back({ {"/objects/getImage.php", "base64Url"}, "youphptube-encoder-cve-2019-5127" });
    rules.push_back({ {"/yyoa/common/js/menu/test.jsp", "S1"}, "yongyou-u8-oa-sqli" });
    rules.push_back({ {"/Proxy"}, "yonyou-grp-u8-sqli-to-rce" });
    rules.push_back({ {"/servlet/FileReceiveServlet"}, "yonyou-nc-arbitrary-file-upload" });
    rules.push_back({ {"/objects/getSpiritsFromVideo.php", "base64Url"}, "youphptube-encoder-cve-2019-5129" });
    rules.push_back({ {"/objects/getImageMP4.php", "base64Url"}, "youphptube-encoder-cve-2019-5128" });
    rules.push_back({ {"/member/cart/Fastpay", "shopid"}, "yungoucms-sqli" });
    rules.push_back({ {"/zabbix.php", "action=dashboard.view"}, "zabbix-authentication-bypass" });
    rules.push_back({ {"/jsrpc.php", "profileIdx2"}, "zabbix-cve-2016-10134-sqli" });
    rules.push_back({ {"/admin/cms_channel.php", "del"}, "zcms-v3-sqli" });
    rules.push_back({ {"/_next/static/", "/server/pages-manifest.json"}, "zeit-nodejs-cve-2020-5284-directory-traversal" });
    rules.push_back({ {"/cgi-bin/kerbynet", "Action"}, "zeroshell-cve-2019-12725-rce" });
    rules.push_back({ {"/Autodiscover/Autodiscover.xml"}, "zimbra-cve-2019-9670-xxe" });
    rules.push_back({ {"/user/zs.php", "do=save"}, "zzcms-zsmanage-sqli" });
    rules.push_back({ {"/user/zsmanage.php"}, "zzcms-zsmanage-sqli" });
    // 添加更多规则...
    return rules;
}

// 函数用于匹配规则并输出匹配结果
void matchRule(const std::vector<Rule>& rules, const std::string& logFileName) {
    std::ifstream logFile(logFileName);
    if (!logFile.is_open()) {
        std::cerr << "无法打开日志文件" << std::endl;
        return;
    }

    std::string line;
    int lineNumber = 0; // 记录行数

    while (std::getline(logFile, line)) {
        lineNumber++; // 增加行数

        for (const auto& rule : rules) {
            bool allKeywordsMatch = true;
            for (const auto& keyword : rule.keywords) {
                if (line.find(keyword) == std::string::npos) {
                    allKeywordsMatch = false;
                    break;
                }
            }

            if (allKeywordsMatch) {
                std::cout << "匹配到规则 (行号 " << lineNumber << "): " << line << " 规则名称: " << rule.ruleName << std::endl;
                //break; // 一旦匹配到规则，跳出内层循环
            }
        }
    }

    logFile.close();
}


int main() {
    std::string logFileName;

    std::cout << "请输入日志文件名：";
    std::cin >> logFileName;

    // 调用获取规则的函数
    std::vector<Rule> rules = getRules();

    // 调用匹配规则的函数
    matchRule(rules, logFileName);

    return 0;
}