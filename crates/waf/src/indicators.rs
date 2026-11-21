//! Weighted attack indicators, grouped by attack class.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AttackClass {
    SqlInjection,
    CrossSiteScripting,
    PathTraversal,
    CommandInjection,
    Ssrf,
    JndiInjection,
    Xxe,
    TemplateInjection,
    NoSqlInjection,
    PhpInjection,
    JavaInjection,
    RemoteFileInclusion,
    CodeInjection,
    PrototypePollution,
    SessionFixation,
}

impl AttackClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackClass::SqlInjection => "sql_injection",
            AttackClass::CrossSiteScripting => "xss",
            AttackClass::PathTraversal => "path_traversal",
            AttackClass::CommandInjection => "command_injection",
            AttackClass::Ssrf => "ssrf",
            AttackClass::JndiInjection => "jndi_injection",
            AttackClass::Xxe => "xxe",
            AttackClass::TemplateInjection => "template_injection",
            AttackClass::NoSqlInjection => "nosql_injection",
            AttackClass::PhpInjection => "php_injection",
            AttackClass::JavaInjection => "java_injection",
            AttackClass::RemoteFileInclusion => "remote_file_inclusion",
            AttackClass::CodeInjection => "code_injection",
            AttackClass::PrototypePollution => "prototype_pollution",
            AttackClass::SessionFixation => "session_fixation",
        }
    }
}

use AttackClass::*;

pub(crate) struct Indicator {
    pub(crate) class: AttackClass,
    pub(crate) name: &'static str,
    pub(crate) weight: f64,
    pub(crate) pattern: &'static str,
}

const CMDS: &str = r"(cat|ls|id|whoami|uname|wget|curl|nc|ncat|netcat|bash|sh|zsh|ksh|powershell|pwsh|cmd|ping|nslookup|dig|python[23]?|perl|ruby|php|rm|chmod|chown|echo|printenv|env|ifconfig|ipconfig|systeminfo|tasklist|base64|telnet|ssh|scp)";
const MONGO_OPS: &str =
    r"(ne|eq|gt|gte|lt|lte|in|nin|regex|exists|where|expr|or|and|not|nor|elemmatch|function)";

pub(crate) fn indicators() -> Vec<Indicator> {
    let i = |class, name, weight, pattern: &'static str| Indicator {
        class,
        name,
        weight,
        pattern,
    };
    let cmd_chain: &'static str = Box::leak(
        format!(r"([;&|\n]|\$\()\s*{CMDS}(\s*$|\s*[;&|`)]|\s+[-/]|\s+(https?|ftp)://|\s+\$)")
            .into_boxed_str(),
    );
    let backtick_args: &'static str = Box::leak(format!(r"`\s*{CMDS}\s+[^`]+`").into_boxed_str());
    let backtick_bare: &'static str = Box::leak(format!(r"`\s*{CMDS}\s*`").into_boxed_str());
    let abs_cmd: &'static str =
        Box::leak(format!(r"(^|[;&|(\s])/(usr/)?s?bin/{CMDS}\b").into_boxed_str());
    let mongo_bracket: &'static str = Box::leak(
        format!(r#"\[\s*\${MONGO_OPS}\s*\]|"\${MONGO_OPS}"\s*:|^\${MONGO_OPS}$"#).into_boxed_str(),
    );
    vec![
        // ---- SQL injection ----
        i(
            SqlInjection,
            "union_select",
            8.0,
            r"\bunion(\s+(all|distinct))?\s*\(?\s*select\b",
        ),
        i(
            SqlInjection,
            "quote_tautology",
            7.0,
            r#"['"]\s*\)*\s*(or|and|\|\||&&)\s*\(*\s*['"]?\w*['"]?\s*\)*\s*(=|<>|!=|<|>|\blike\b|\bis\s+(not\s+)?(null|true|false)\b|[-*^&|+/%])"#,
        ),
        i(
            SqlInjection,
            "quote_boolean",
            4.0,
            r#"['"]\s*\)*\s*(or|and)\s+(true|false|not|\d+)\b"#,
        ),
        i(
            SqlInjection,
            "quote_block_comment",
            3.0,
            r#"['"]\s*\)*\s*/\*"#,
        ),
        i(
            SqlInjection,
            "numeric_tautology",
            7.0,
            r"\b(or|and)\s+\(*\s*(\d+|'\d+')\s*(=|<>|!=)\s*(\d+|'\d+')",
        ),
        i(
            SqlInjection,
            "quote_and_function",
            5.0,
            r#"['"]\s*\)?\s*(or|and)\s+\w+\s*\("#,
        ),
        i(
            SqlInjection,
            "quote_comment",
            4.0,
            r#"['"]\s*\)*\s*(--|#|;|/\*)"#,
        ),
        i(
            SqlInjection,
            "quote_line_comment_end",
            3.0,
            r#"['"]\s*\)*\s*(--(\s|-|$)|#\s*$)"#,
        ),
        i(
            SqlInjection,
            "paren_comment_end",
            2.0,
            r"\)\s*(--(\s|-|$)|#\s*$)",
        ),
        i(
            SqlInjection,
            "operator_time_function",
            3.0,
            r"(\bor\b|\band\b|\|\||&&|,|\(|=)\s*(sleep|pg_sleep|benchmark)\s*\(",
        ),
        i(
            SqlInjection,
            "order_by_injection",
            3.0,
            r"\border\s+by\s+[\d,\s]*(sleep|benchmark|if|case|select|\()",
        ),
        i(
            SqlInjection,
            "ddl_statement",
            3.0,
            r"\b(drop|truncate|alter)\s+(table|database|schema|column|user)\b|\bdelete\s+from\b|\binsert\s+into\b",
        ),
        i(
            SqlInjection,
            "stacked_query",
            6.0,
            r";\s*(drop|delete|insert|update|alter|create|truncate|exec(ute)?|declare|shutdown|grant|revoke)\b",
        ),
        i(
            SqlInjection,
            "time_based",
            6.0,
            r"\b(sleep|pg_sleep)\s*\(\s*\d|\bbenchmark\s*\(\s*\d|\bwaitfor\s+delay\b|\bdbms_lock\.sleep",
        ),
        i(
            SqlInjection,
            "schema_probe",
            6.0,
            r"\b(information_schema|sysobjects|syscolumns|pg_catalog|sqlite_master|mysql\.user|all_tables|sys\.tables)\b",
        ),
        i(
            SqlInjection,
            "dangerous_function",
            7.0,
            r"\b(load_file|xp_cmdshell|utl_http|sp_oacreate)\b|\binto\s+(out|dump)file\b",
        ),
        i(
            SqlInjection,
            "select_from",
            3.0,
            r"\bselect\b[\s\S]{1,100}?\bfrom\b",
        ),
        i(
            SqlInjection,
            "sql_function",
            2.0,
            r"\b(concat|concat_ws|group_concat|char|chr|ascii|substring|substr|mid|hex|unhex|extractvalue|updatexml|cast|convert|md5|sha1|if|ifnull|iif|nullif)\s*\(",
        ),
        i(
            SqlInjection,
            "fingerprint_function",
            4.0,
            r"@@version|@@datadir|\bversion\s*\(\s*\)|\b(current_user|database|user|schema)\s*\(\s*\)",
        ),
        i(
            SqlInjection,
            "boolean_literal",
            3.0,
            r"\b(or|and)\s+(true|false|null)\b",
        ),
        i(
            SqlInjection,
            "order_by_probe",
            7.0,
            r"\border\s+by\s+\d+\s*(--|#)",
        ),
        i(
            SqlInjection,
            "having_probe",
            6.0,
            r"\bhaving\s+\d+\s*=\s*\d+",
        ),
        i(
            SqlInjection,
            "sql_json_operator",
            4.0,
            r#"::\s*jsonb?\b|\bjsonb?_(extract\w*|pretty|each\w*|object_keys|array_elements\w*|typeof|path_\w+)\s*\(|['"]\s*(->>?|#>>?|<@|@>|\?\||\?&)\s*['"\[]|\barray\s*\[[^\]]*\]\s*(<@|@>|&&)"#,
        ),
        i(
            SqlInjection,
            "sql_logic_json",
            4.0,
            r#"\b(or|and)\s+(json\w*\s*\(|'\s*[\[{])"#,
        ),
        i(
            SqlInjection,
            "sql_stored_procedure",
            6.0,
            r"\bprocedure\s+analyse\s*\(|\bdeclare\s+@|\bexec(ute)?\s*\(\s*@|\bexec(ute)?\s+(master\.|xp_|sp_)|\b(sp_executesql|sp_makewebtask|sp_addextendedproc|sp_password)\b",
        ),
        i(
            SqlInjection,
            "sql_case_when",
            3.0,
            r"\bcase\s+when\b[\s\S]{1,200}?\bthen\b",
        ),
        i(
            SqlInjection,
            "sql_integer_overflow",
            5.0,
            r"^\s*(-?0000023456|4294967295|4294967296|2147483648|2147483647|-2147483648|-2147483649|0000012345|2\.2250738585072007e-308|2\.2250738585072011e-308|1e309)\s*$",
        ),
        i(
            SqlInjection,
            "float_parsing_dos",
            7.0,
            r"^\s*(2\.2250738585072011e-308|2\.2250738585072012e-308|1e309)\s*$",
        ),
        // ---- cross-site scripting ----
        i(CrossSiteScripting, "script_tag", 8.0, r"<\s*/?\s*script\b"),
        i(
            CrossSiteScripting,
            "js_uri",
            3.0,
            r"\b(java|vb|live)script\s*:",
        ),
        i(
            CrossSiteScripting,
            "js_uri_call",
            7.0,
            r"\b(java|vb)script\s*:\s*[\w.\[\]]+\s*[(`]",
        ),
        i(
            CrossSiteScripting,
            "tag_event_handler",
            8.0,
            r"<[a-z][\w-]*[^>]*?[\s/]on[a-z]{3,}\s*=",
        ),
        i(
            CrossSiteScripting,
            "event_handler",
            4.0,
            r"\bon(error|load|mouseover|mouseenter|focus|blur|click|toggle|animationstart|transitionend|pointerover|begin|start|unload|beforeunload|message|hashchange|input|change|submit|keydown|keyup|wheel)\s*=",
        ),
        i(
            CrossSiteScripting,
            "dangerous_tag",
            4.0,
            r"<\s*(iframe|frame|object|embed|svg|math|base|meta|link|form|img|video|audio|body|details|marquee|isindex|applet|style|template)\b",
        ),
        i(
            CrossSiteScripting,
            "dom_sink",
            4.0,
            r"\b(document\s*\.\s*(cookie|domain|write|location)|window\s*\.\s*location|localstorage|sessionstorage|innerhtml|outerhtml)\b",
        ),
        i(
            CrossSiteScripting,
            "js_string_breakout",
            5.0,
            r#"['"]\s*[-+*/;,|&]\s*(alert|prompt|confirm|eval)\s*[(`]"#,
        ),
        i(
            CrossSiteScripting,
            "js_exec_call",
            3.0,
            r"\b(alert|prompt|confirm|eval|settimeout|setinterval|atob)\s*(\(|`)",
        ),
        i(
            CrossSiteScripting,
            "srcdoc",
            5.0,
            r"\b(srcdoc|formaction|xlink:href)\s*=",
        ),
        i(
            CrossSiteScripting,
            "css_expression",
            4.0,
            r"expression\s*\(|-moz-binding|\bbehavior\s*:",
        ),
        i(
            CrossSiteScripting,
            "data_uri_html",
            5.0,
            r"data\s*:\s*(text/html|text/javascript|application/javascript)",
        ),
        i(
            CrossSiteScripting,
            "html_breakout",
            4.0,
            r#"['"]\s*/?>\s*<"#,
        ),
        // ---- path traversal ----
        i(PathTraversal, "dotdot", 3.0, r"\.\.[/\\]"),
        i(PathTraversal, "dotdot_multi", 3.0, r"(\.\.[/\\]){2,}"),
        i(PathTraversal, "dotdot_deep", 2.0, r"(\.\.[/\\]){4,}"),
        i(
            PathTraversal,
            "sensitive_file",
            7.0,
            r"/etc/(passwd|shadow|group|hosts|issue)\b|/proc/(self|\d+)/|\bc:\\\\?windows\\|\bboot\.ini\b|\bwin\.ini\b|/\.ssh/|\bweb-inf/web\.xml|/\.env\b|/\.git/|/\.aws/",
        ),
        // ---- command injection ----
        i(CommandInjection, "shell_chain", 7.0, cmd_chain),
        i(
            CommandInjection,
            "command_substitution",
            4.0,
            r"\$\(\s*[a-z]+[^)]*\)",
        ),
        i(
            CommandInjection,
            "backtick_command_args",
            7.0,
            backtick_args,
        ),
        // `ls` is also how people write code in Markdown: log, don't block, on its own.
        i(CommandInjection, "backtick_command", 4.0, backtick_bare),
        i(CommandInjection, "absolute_path_command", 7.0, abs_cmd),
        i(
            CommandInjection,
            "ssi_directive",
            8.0,
            r"<!--\s*#\s*(exec|include|echo|config|printenv)\b",
        ),
        i(
            CommandInjection,
            "shell_path",
            6.0,
            r"(/bin/(ba|z|da)?sh\b|/usr/bin/(env|python|perl)\b|\bcmd(\.exe)?\s+/c\b|powershell(\.exe)?\s+-)",
        ),
        i(
            CommandInjection,
            "reverse_shell",
            6.0,
            r"/dev/(tcp|udp)/|>\s*/dev/null|\bnc\s+-[elvnp]",
        ),
        i(CommandInjection, "ifs_evasion", 5.0, r"\$\{?ifs\}?"),
        // ---- server-side request forgery ----
        i(
            Ssrf,
            "cloud_metadata",
            8.0,
            r"\b169\.254\.169\.254\b|\bmetadata\.google\.internal\b|\b100\.100\.100\.200\b|\bfd00:ec2::254\b|/latest/meta-data",
        ),
        i(
            Ssrf,
            "dangerous_scheme",
            7.0,
            r"\b(gopher|dict|ldap|tftp|jar|netdoc|expect|phar|local_file)://",
        ),
        i(Ssrf, "file_scheme", 6.0, r"\bfile://"),
        i(
            Ssrf,
            "internal_url",
            5.0,
            r"\bhttps?://(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|0x7f\w*|2130706433|\[::1?\]|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)",
        ),
        // ---- JNDI / Log4Shell ----
        i(JndiInjection, "jndi_lookup", 10.0, r"\$\{\s*jndi\s*:"),
        i(
            JndiInjection,
            "nested_lookup",
            6.0,
            r"\$\{[^}]{0,40}\$\{|\$\{\s*(lower|upper|env|sys|date|main|ctx|base64|::-)",
        ),
        i(
            JndiInjection,
            "jndi_protocol",
            3.0,
            r"\b(ldaps?|rmi|iiop|corba|nds|nis)://",
        ),
        // ---- XML external entities ----
        i(Xxe, "entity_declaration", 6.0, r"<!entity\b"),
        i(
            Xxe,
            "external_entity",
            4.0,
            r"<!entity[^>]*\b(system|public)\b",
        ),
        i(Xxe, "doctype_subset", 3.0, r"<!doctype[^>]*\["),
        i(Xxe, "xinclude", 5.0, r"xi:include|xmlns:xi\s*="),
        // ---- server-side template injection ----
        i(
            TemplateInjection,
            "template_math",
            7.0,
            r#"\{\{\s*\d+\s*[*+\-/]\s*['"]?\d+['"]?\s*\}\}|\$\{\s*\d+\s*[*+\-/]\s*['"]?\d+['"]?\s*\}|<%=\s*\d+\s*[*+]\s*\d+\s*%>|#\{\s*\d+\s*[*+]\s*\d+\s*\}"#,
        ),
        i(
            TemplateInjection,
            "template_dangerous_name",
            7.0,
            r"(\{\{|\{%|\$\{|<%|#\{)[^}%>]{0,300}(\bself\b|\brequest\b|\bconfig\b|\bapp\.|getclass\s*\(|\|\s*attr\b|\bos\.(system|popen)|\bpopen\b|subprocess|forname\s*\(|newinstance\s*\(|scriptengine|\.iteritems\s*\(|\bimport\s+os\b|\bsystem\s*\()",
        ),
        i(
            TemplateInjection,
            "template_object_access",
            8.0,
            r"(\{\{|\{%|\$\{|<%)[^}%>]{0,200}(__class__|__globals__|__builtins__|__mro__|__subclasses__|config\.items|request\.application|self\._|lipsum|cycler|joiner|getruntime|processbuilder|freemarker\.template|\bexec\s*\()",
        ),
        // ---- PHP code injection ----
        i(PhpInjection, "php_open_tag", 5.0, r"<\?(php\b|=)"),
        i(
            PhpInjection,
            "php_tag_with_code",
            7.0,
            r"<\?(php\b|=|\s)\s*(echo\b|print\b|\$\w|[a-z_]\w*\s*\()",
        ),
        i(
            PhpInjection,
            "php_tag_with_execution",
            8.0,
            r"<\?(php\b|=|\s)[\s\S]{0,300}?(`|\b(system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|eval|assert|include|require|include_once|require_once|base64_decode|file_put_contents|fwrite|fputs)\s*\()",
        ),
        i(
            PhpInjection,
            "php_superglobal",
            3.0,
            r"\$_(get|post|request|cookie|server|files|env|session)\b",
        ),
        i(
            PhpInjection,
            "php_stream_wrapper",
            7.0,
            r"\bphp://(filter|input|fd|memory|temp|stdin)|\bdata://text/plain|\b(compress\.zlib|compress\.bzip2|glob)://",
        ),
        i(
            PhpInjection,
            "php_serialized_object",
            7.0,
            r#"\bo:\d+:"[a-z0-9_\\]+":\d+:\{"#,
        ),
        i(
            PhpInjection,
            "php_obfuscated_call",
            7.0,
            r#"["'](system|exec|passthru|shell_exec|assert|eval|popen|proc_open|pcntl_exec)["']\s*\(|\(\s*["']?(system|exec|passthru|shell_exec|assert|popen|proc_open)["']?\s*\)\s*\(|\[\s*["']?(system|exec|passthru|shell_exec|assert|popen|proc_open)["']?\s*\](\s*\[[^\]]*\])*\s*\("#,
        ),
        i(
            PhpInjection,
            "php_variable_function",
            4.0,
            r#"\$\{?[\w$]+\}?(\s*(\[[^\]]{0,40}\]|\{[^}]{0,40}\}))*\s*\(|\$\{\s*[$'"]"#,
        ),
        i(
            PhpInjection,
            "script_upload",
            7.0,
            r#"filename\s*=\s*"?[^"\r\n]*\.(php\d?|phtml|phar|pht|phps|asp|aspx|jsp|jspx|cgi)"?(\s|;|$)"#,
        ),
        i(
            PhpInjection,
            "php_dangerous_call",
            4.0,
            r"\b(eval|assert|system|passthru|shell_exec|popen|proc_open|pcntl_exec|create_function|call_user_func(_array)?)\s*\(",
        ),
        // ---- Java attacks (deserialization, expression / class abuse) ----
        i(
            JavaInjection,
            "java_serialized_object",
            8.0,
            r"\b(ro0ab|kztaau|cs7qaf|aced0005)",
        ),
        i(
            JavaInjection,
            "java_gadget",
            7.0,
            r"(rocessbuilder|nvokertransformer|nstantiatetransformer|nstantiatefactory|lonetransformer|hainedtransformer|onstanttransformer|\bforclosure|hileclosure|rototypeclonefactory|rototypeserializationfactory|emplatesimpl|\bxmldecoder)|runtime\s*\.\s*getruntime\s*\(|\bclass\.module\.classloader|\bjava\.lang\.reflect\.|\bjavax\.script\.scriptenginemanager",
        ),
        i(
            JavaInjection,
            "java_dotted_exec",
            7.0,
            r"\bjava\.[a-z0-9_.]{0,60}\b(runtime|processbuilder)\b",
        ),
        // ---- server-side JavaScript (Node.js) and Perl code injection ----
        i(
            CodeInjection,
            "node_deserialization",
            8.0,
            r"_\$\$nd_func\$\$_|\b__js_function\b",
        ),
        i(
            CodeInjection,
            "node_function_constructor",
            7.0,
            r"\bnew\s+function\s*\(|\bconstructor\s*\.\s*constructor\b|\bconstructor\s*\[\s*['\x22]constructor",
        ),
        i(
            CodeInjection,
            "node_module_loading",
            7.0,
            r#"\brequire\s*\(\s*['"`]?(child_process|fs|net|vm|os|http|https|dgram|cluster|worker_threads)\b|\brequire\s*\[|\brequire\.main\b|\bconstructor\s*\.\s*_load\s*\(|\bprocess\s*\.\s*(mainmodule|binding|dlopen)\b|\bprocess\s*\[|\bglobal\s*\.\s*process\b"#,
        ),
        i(
            CodeInjection,
            "node_child_process",
            6.0,
            r"\bchild_process\b|\.\s*(execsync|spawnsync|execfilesync)\s*\(",
        ),
        i(
            CodeInjection,
            "node_process_env",
            5.0,
            r"\bprocess\s*\.\s*env\b",
        ),
        i(
            CodeInjection,
            "node_module_exports",
            5.0,
            r"\bmodule\s*\.\s*exports\s*=",
        ),
        i(
            CodeInjection,
            "node_console_call",
            4.0,
            r#"\bconsole\s*(\.\s*|\[\s*['"])(log|info|warn|error|debug|trace|dir)\b"#,
        ),
        i(
            CodeInjection,
            "eval_decoded_string",
            7.0,
            r"\b(eval|function|settimeout|setinterval)\s*\(\s*(string\s*\.\s*fromcharcode|atob|buffer\s*\.\s*from|unescape|decodeuricomponent)\s*\(",
        ),
        i(
            CodeInjection,
            "react_flight_gadget",
            8.0,
            r#""\$[0-9a-f@]*:(__proto__|constructor|prototype)\b|"\$[0-9a-f]*:[a-z_]*:(__proto__|constructor|prototype)\b|\bresolved_model\b[\s\S]{0,200}\b_response\b"#,
        ),
        i(
            CodeInjection,
            "node_event_loop_block",
            7.0,
            r"\bwhile\s*\(\s*!\s*[-+]?\s*(0|false|\[\s*\]|''|\x22\x22)\s*\)|\bfor\s*\(\s*;\s*;\s*\)\s*[{;]?\s*[};]",
        ),
        i(CodeInjection, "perl_interpolation", 7.0, r"@\{\s*\["),
        // ---- prototype pollution ----
        i(
            PrototypePollution,
            "proto_property",
            7.0,
            r#"\b__proto__\b|\bconstructor\s*(\.|\[\s*['"]?)\s*prototype\b"#,
        ),
        // ---- expression language / Velocity ----
        i(
            TemplateInjection,
            "velocity_directive",
            4.0,
            r"#\s*(set|foreach|if|elseif|macro|evaluate|define|parse|include)\s*\(\s*[$\[]",
        ),
        i(
            TemplateInjection,
            "reflection_call",
            4.0,
            r"\.\s*(getmethod|getdeclaredmethod|getdeclaredfield|invoke|forname|getclass|newinstance|getconstructor|getruntime)\s*\(",
        ),
        i(
            TemplateInjection,
            "expression_language_exec",
            7.0,
            r"[#$]\{[^}]{0,200}\b(runtime|processbuilder|\.exec\s*\(|invoke\s*\(|getclass\s*\(|forname\s*\()",
        ),
        i(
            TemplateInjection,
            "template_control_block",
            5.0,
            r"\{%-?\s*(if|for|set|import|include|macro|raw|debug)\b[^%]{0,200}%\}[\s\S]{0,300}\{%-?\s*end|<%=?\s*(if|for|each|unless)\b[^%]{0,200}%>[\s\S]{0,300}<%\s*end",
        ),
        // ---- session fixation: setting the victim's cookie (CRS 943100) ----
        i(
            SessionFixation,
            "cookie_setting",
            7.0,
            r"\.cookie\b.*?;\W*?(expires|domain)\W*?=|\bhttp-equiv\W+set-cookie\b",
        ),
        // ---- NoSQL injection ----
        i(NoSqlInjection, "mongo_operator", 7.0, mongo_bracket),
        i(NoSqlInjection, "mongo_where", 8.0, r#"\$where\b"#),
    ]
}
