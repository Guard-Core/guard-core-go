package guardcore

import (
	"sort"
	"strings"
)

type patternDef struct {
	Pattern  string
	Contexts []string
	Category string
}

var patternTable = []patternDef{
	{Pattern: "<script[^>]*>[^<]*<\\/script\\s*>", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xss"},
	{Pattern: "javascript:\\s*[^\\s]+", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xss"},
	{Pattern: "j[\\t\\r\\n]*a[\\t\\r\\n]*v[\\t\\r\\n]*a[\\t\\r\\n]*s[\\t\\r\\n]*c[\\t\\r\\n]*r[\\t\\r\\n]*i[\\t\\r\\n]*p[\\t\\r\\n]*t[\\t\\r\\n]*:\\s*[^\\s]+", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xss"},
	{Pattern: "(?:<[A-Za-z/](?:[^<>]*[^<>\\s/])?(?<!=)(?<!=\\\")(?<!=')[\\s/]+(?:onwebkitplaybacktargetavailabilitychanged|oncontentvisibilityautostatechange|onwebkitpresentationmodechanged|onwebkitmouseforcewillbegin|onwebkitanimationiteration|onsecuritypolicyviolation|onwebkitmouseforcechanged|onvalidationstatuschange|onwebkitfullscreenchange|onwebkitwillrevealbottom|onwebkitanimationstart|onwebkitmouseforcedown|onbeforescriptexecute|onmozfullscreenchange|onwebkittransitionend|onafterscriptexecute|onanimationiteration|onlostpointercapture|onscrollsnapchanging|onunhandledrejection|onwebkitanimationend|onwebkitmouseforceup|ondeviceorientation|ongotpointercapture|onbeforedeactivate|onfullscreenchange|onpointerrawupdate|onreadystatechange|onrejectionhandled|onscrollsnapchange|ontransitioncancel|onanimationcancel|onbeforeeditfocus|oncontextrestored|ondatasetcomplete|onselectionchange|ontransitionstart|onanimationstart|onbeforeactivate|oncanplaythrough|ondatasetchanged|ondurationchange|onlanguagechange|onlayoutcomplete|onloadedmetadata|onpropertychange|oncontrolselect|ondataavailable|ongesturechange|onmediacomplete|onpointercancel|onpromptdismiss|ontransitionend|ontransitionrun|onwebkitneedkey|onanimationend|onbeforetoggle|onbeforeunload|onbeforeupdate|ondevicemotion|onfilterchange|ongesturestart|onmessageerror|onpointerenter|onpointerleave|onpromptaction|onsyncrestored|onvolumechange|onafterupdate|onbeforeinput|onbeforematch|onbeforepaste|onbeforeprint|oncontextlost|oncontextmenu|onerrorupdate|onlosecapture|onpointerdown|onpointermove|onpointerover|onresizestart|onrowinserted|onselectstart|ontouchcancel|ontrackchange|onafterprint|onbeforecopy|oncellchange|ondeactivate|ongestureend|onhashchange|onloadeddata|onmediaerror|onmouseenter|onmouseleave|onmousewheel|onpagereveal|onpointerout|onratechange|onslotchange|ontimeupdate|ontouchstart|onbeforecut|oncuechange|ondragenter|ondragleave|ondragstart|onloadstart|onmousedown|onmousemove|onmouseover|onmovestart|onoutofsync|onpointerup|onresizeend|onrowdelete|onrowsenter|onscrollend|ontimeerror|ontouchmove|onactivate|onauxclick|ondblclick|ondragdrop|ondragexit|ondragover|onfocusout|onformdata|onkeypress|onlocation|onmouseout|onpagehide|onpageshow|onpageswap|onpopstate|onprogress|ontouchend|oncanplay|oncommand|ondragend|onemptied|onfocusin|oninvalid|onkeydown|onmessage|onmouseup|onmoveend|onoffline|onplaying|onreverse|onrowexit|onseeking|onstalled|onstorage|onsuspend|onurlflip|onwaiting|onbounce|oncancel|onchange|onfinish|ononline|onrepeat|onresize|onresume|onscroll|onsearch|onseeked|onselect|onsubmit|ontoggle|onunload|onabort|onbegin|onclick|onclose|onended|onerror|onfocus|oninput|onkeyup|onpaste|onpause|onreset|onstart|onwheel|onblur|oncopy|ondrag|ondrop|onhelp|onload|onmove|onplay|onredo|onseek|onstop|onundo|oncut|onend)\\s*=\\s{0,20}(?:[\\\"'][^\\\"']*[\\\"']|[^\\s>]+))", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xss"},
	{Pattern: "(?:<[A-Za-z/](?:[^<>]*[^<>\\s])?\\s+(?:href|src|data|action)\\s*=[\\s\\\"\\']*(?:javascript|vbscript|data):)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xss"},
	{Pattern: "(?:<[A-Za-z/][^<>]*style\\s*=\\s{0,20}[\\\"']?[^<>\\\"']*(?:expression|behavior|url)\\s*\\([^)]*\\))", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xss"},
	{Pattern: "(?:<object[^>]*>[\\s\\S]*<\\/object\\s*>)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xss"},
	{Pattern: "(?:<embed[^>]*>[\\s\\S]*<\\/embed\\s*>)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xss"},
	{Pattern: "(?:<applet[^>]*>[\\s\\S]*<\\/applet\\s*>)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xss"},
	{Pattern: "(?i)\\bSELECT\\b(?:(?!\\bSELECT\\b)[\\w\\s,\\*().])*?\\bFROM\\b", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)SELECT\\s+\\*", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)\\bWHERE\\s+[\\w.\"]+\\s*(?:=|<|>|<=|>=|LIKE|IN)\\b", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)\\b(?:OR|AND)\\s*(\\d+|'[^']*'|\\\"[^\\\"]*\\\"|[@:$][A-Za-z_]\\w*)\\s*=\\s*\\1\\b", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)UNION\\s+(?:ALL\\s+)?SELECT", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)('\\s*(?:OR|AND)[\\s(]*'?(?:[@:$][A-Za-z_]\\w*|[\\d\\w]+)\\s*(?:LIKE|[<>]=?|=)[\\s(]*'?(?:[@:$][A-Za-z_]\\w*|[\\d\\w]+))", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)(UNION\\s+(?:ALL\\s+)?SELECT\\s+NULL(?:[,\\s]*NULL)*[,\\s]*|\\(\\s*SELECT\\s+(?:@@|VERSION))", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)(?:INTO\\s+(?:OUTFILE|DUMPFILE)\\s+'[^']+')", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)(?:LOAD_FILE\\s*\\([^)]+\\))", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)(?:BENCHMARK\\s*\\(\\s*\\d+\\s*,)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)(?:SLEEP\\s*\\(\\s*\\d+\\s*\\))", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)(?:\\/\\*![0-9]*\\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|CONCAT|CHAR|UPDATE)\\b)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "\\w/\\*(?!!)[^*]*\\*/\\w", Contexts: []string{"query_param", "request_body", "unknown"}, Category: "sqli"},
	{Pattern: "(?i)(?:OR|AND)\\s+(?:'[\\w\\d]*'='[\\w\\d]*'?|[@:$][A-Za-z_]\\w*\\s*=\\s*[@:$][A-Za-z_]\\w*)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i);\\s*(?:DROP|TRUNCATE|ALTER|CREATE)\\s+(?:TABLE|DATABASE|SCHEMA)\\b", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i);\\s*(?:INSERT\\s+INTO|UPDATE\\s+\\w+\\s+SET|DELETE\\s+FROM|SELECT\\b[^;]*?\\bFROM\\b|REPLACE\\s+INTO)\\b", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)\\bEXEC(?:UTE)?\\s+(?:xp_\\w+|sp_\\w+)", Contexts: []string{"query_param", "request_body", "unknown"}, Category: "sqli"},
	{Pattern: "(?i)(?:\\A|[;'\\\"])\\s*EXEC(?:UTE)?\\s+(?:xp_\\w+|sp_\\w+)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)\\bORDER\\s+BY\\s+\\d+\\s*(?:--|#|;|\\)|,|/\\*|\\Z)|(?<=[=?&])ORDER\\s+BY\\s+\\d+\\s*\\n", Contexts: []string{"query_param", "request_body", "unknown"}, Category: "sqli"},
	{Pattern: "(?i)(?:['\\\")\\d]|/\\*)\\s{0,3}\\bORDER\\s+BY\\s+\\d+|\\bORDER\\s+BY\\s+\\d+\\s*(?:--|#|/\\*)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: sqliCommentTerminatorSource, Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?i)\\bWAITFOR\\s+(?:DELAY|TIME)\\s+'\\d{1,2}:\\d{1,2}:\\d{1,2}(?:\\.\\d+)?'", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "sqli"},
	{Pattern: "(?:\\.\\.\\/|\\.\\.\\\\)(?:\\.\\.\\/|\\.\\.\\\\)+", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "dir_traversal"},
	{Pattern: "\\A(?:(?!\\n).)*etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\\.cnf|ssh/ssh_config)(?:[&#;,\\\"'<>]|\\s*\\Z)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "dir_traversal"},
	{Pattern: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\\.cnf|ssh/ssh_config))(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "dir_traversal"},
	{Pattern: "\\A(?:(?!\\n).)*(?:boot\\.ini|win\\.ini|system\\.ini|config\\.sys)(?:[&#;,\\\"'<>]|\\s*\\Z)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "dir_traversal"},
	{Pattern: "\\A(?:(?!\\n).)*proc/self/environ(?:[&#;,\\\"'<>]|\\s*\\Z)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "dir_traversal"},
	{Pattern: "\\A(?:(?!\\n).)*var/log/[^\\s/]+(?:[&#;,\\\"'<>]|\\s*\\Z)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "dir_traversal"},
	{Pattern: "\\.\\.;[^/\\\\]*[/\\\\]", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "dir_traversal"},
	{Pattern: ";\\s*(?:ls|cat|rm|chmod|chown|wget|curl|nc|netcat|ping|telnet)\\s+-[a-zA-Z]+\\s+", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "\\|\\s*(?:wget|curl|fetch|lwp-download|lynx|links|GET)\\s+", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "(?:[;&|]\\s*(?:\\$\\([^)]+\\)|\\$\\{[^}]+\\}))", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "\\A\\s*(?:[;&|]\\s*)*`\\s*(?:[A-Za-z0-9_./~]|\\$[({])(?:[^`\\\\\\n]|\\\\.)*(?:\\n\\s*)?`(?:\\s*[;&|]\\s*`\\s*(?:[A-Za-z0-9_./~]|\\$[({])(?:[^`\\\\\\n]|\\\\.)*(?:\\n\\s*)?`)*\\s*(?:[;&|]\\s*)*\\Z", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "(?<!`)`(?:[A-Za-z0-9_./~]|\\$[({])(?:[^`\\\\\\n]|\\\\.)*`", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "cmd_injection"},
	{Pattern: "\\$\\((?:[^()\\\\\\n]|\\\\.)*\\)|\\$\\{(?:[^{}\\\\\\n]|\\\\.)*\\}", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "cmd_injection"},
	{Pattern: "(?i)\\$\\{(?:jndi:(?:ldap|rmi|dns)://|\\$?\\{?(?:lower|upper):j\\}ndi|::-j\\}ndi)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "cmd_injection"},
	{Pattern: "(?:\\A|[;|&])\\s*/?(?:[\\w.-]+/)*(?:env\\s+/?(?:[\\w.-]+/)*)?(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-[a-zA-Z]+(?:\\s+(?:'[^']*'|\\\"[^\\\"]*\\\"|[^\\s;|&]+))?(?=\\s*(?:[;|&]|\\Z))", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "(?:\\A|[;|&])\\s*[^=\\s;|&]+=[^\\s;|&]+\\s+(?:/?(?:[\\w.-]+/)*env\\s+)?/?(?:[\\w.-]+/)*(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-[a-zA-Z]+", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "\\n[^\\S\\r\\n]*(?:[^=\\s;|&]+=[^\\s;|&]+\\s+)*(?:/?(?:[\\w.-]+/)*env\\s+)?/?(?:[\\w.-]+/)*(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-c\\b", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "\\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open|create_function)\\s*\\(", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "(?:require\\(\\s*[\\\"']child_process[\\\"']\\s*\\)|child_process)\\s*\\.\\s*(?:execSync|spawnSync|spawn|fork)\\s*\\(", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "\\bassert\\s*\\(\\s*\\$", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "\\bos\\.exec(?:l|le|lp|lpe|v|ve|vp|vpe)\\s*\\(", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "\\b(?:new\\s+)?Function\\s*\\(\\s*[\\\"']", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "\\[\\s*[\\\"']eval[\\\"']\\s*\\]\\s*\\(\\s*[\\\"']", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "(?:\\.\\s*constructor|\\[\\s*[\\\"']constructor[\\\"']\\s*\\])\\s*(?:\\.\\s*constructor|\\[\\s*[\\\"']constructor[\\\"']\\s*\\])\\s*\\(\\s*[\\\"']", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "\\b(?:setTimeout|setInterval)\\s*\\(\\s*[\\\"']", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: shellKeywordCommandSource, Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "(?i)\\b(?:nc|netcat|ncat)\\s+-[a-z]*e\\b|/dev/tcp/\\d", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "(?:\\A|[;&|]\\s*|\\$\\()\\{[^{}\\s,:'\\\"][^{},:'\\\"]*(?:,(?:[^{}\\s,:'\\\"][^{},:'\\\"]*)?)+\\}", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "\\w+(?:['\\\"]+\\w+){1,10}", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "[A-Za-z0-9_./*?-]*[?*][A-Za-z0-9_./*?-]*", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "cmd_injection"},
	{Pattern: "(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|rar|ogg|expect)://[^\\s]+", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "file_inclusion"},
	{Pattern: "(?:(?<!:)\\/\\/[0-9a-zA-Z](?:[-\\w]*[0-9a-zA-Z])?(?:\\.[0-9a-zA-Z](?:[-\\w]*[0-9a-zA-Z])?)+(:[0-9]+)?(?:\\/?)(?:[a-zA-Z0-9\\-\\.\\?,'/\\\\\\+&amp;%\\$#_]*)?)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "file_inclusion"},
	{Pattern: "=(?:https?|ftp):\\/\\/[^\\s'\\\"<>]+\\/[^\\s'\\\"<>\\/]*\\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)(?![a-zA-Z0-9])", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "file_inclusion"},
	{Pattern: "[\\\"'](?:template|include|tpl|module|layout)[\\\"']\\s*:\\s*[\\\"'](?:https?|ftp)://[^\\s'\\\"<>]+/[^\\s'\\\"<>/]*\\.(?:phtml|php[3-5]?|phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)(?![a-zA-Z0-9])[\\\"']", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "file_inclusion"},
	{Pattern: "\\([\\s]*[|&][\\s]*\\([^)(]+=[*]", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ldap"},
	{Pattern: "\\*\\s*\\)+\\s*(?:[|&!]\\s*)?\\(+\\s*(?:[&|!]|(?::)?(?:[a-zA-Z][\\w.-]*|\\d+(?:\\.\\d+)*)(?:;[\\w.-]+)*(?::[\\w.-]+)*\\s*:?=)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ldap"},
	{Pattern: "\\)\\s*\\(\\s*(?:[&|!]|(?::)?(?:[a-zA-Z][\\w.-]*|\\d+(?:\\.\\d+)*)(?:;[\\w.-]+)*(?::[\\w.-]+)*\\s*:?[=~<>])", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ldap"},
	{Pattern: "\\(\\s*[&|]\\s*", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ldap"},
	{Pattern: "\\*\\)[|&]?\\(+\\s*(?::)?(?:[a-zA-Z][\\w.-]*|\\d+(?:\\.\\d+)*)(?:;[\\w.-]+)*(?::[\\w.-]+)*\\s*:?=", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ldap"},
	{Pattern: "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ldap"},
	{Pattern: "\\*\\)\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ldap"},
	{Pattern: "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+\\x00", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ldap"},
	{Pattern: "\\*\\)\\)+\\x00", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ldap"},
	{Pattern: "<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xml"},
	{Pattern: "<!DOCTYPE[^>\\[]+PUBLIC[^>\\[]+[\\\"']https?://(?!(?:www\\.)?w3\\.org/)[^\\\"'>]+[\\\"'][^>\\[]*>", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xml"},
	{Pattern: "(?:<!\\[CDATA\\[.*?\\]\\]>)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xml"},
	{Pattern: "<!DOCTYPE[^>\\[]*\\[[\\s\\S]*?<!ENTITY", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "xml"},
	{Pattern: "(?:^|\\s|/)(?:(?<=://)[^\\s/@]*@)?(?:localhost\\.?|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::(?:\\d*)\\]|\\[::ffff:127\\.0\\.0\\.1\\]|169\\.254(?:\\.\\d{1,3}){2}|192\\.168(?:\\.\\d{1,3}){2}|10(?:\\.\\d{1,3}){3}|172\\.(?:1[6-9]|2[0-9]|3[01])(?:\\.\\d{1,3}){2}|metadata\\.google\\.internal|metadata\\.goog|100\\.100\\.100\\.200)(?::\\d+)?(?:\\s|$|/)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ssrf"},
	{Pattern: "://(?:[^/@\\s]*@)?((?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\\d*|0)(?:\\.(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\\d*|0)){0,3})(?=[:/\\s]|$)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ssrf"},
	{Pattern: "(?:file|dict|gopher|jar|tftp)://[^\\s]+", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ssrf"},
	{Pattern: "://[^/\\s@]*@[^/\\s@]*@", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ssrf"},
	{Pattern: "://(?:metadata|instance-data)(?::\\d+)?(?:/|\\s|$)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "ssrf"},
	{Pattern: "\\{\\s*\\$(?:where|gt|lt|ne|eq|regex|in|nin|all|size|exists|type|mod|options):", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "nosql"},
	{Pattern: "(?:\\{\\s*\\$[a-zA-Z]+\\s*:\\s*(?:\\{|\\[))", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "nosql"},
	{Pattern: "\"\\$(?:where|regex|expr|jsonSchema|function|accumulator|type|exists|size)\"\\s*:", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "nosql"},
	{Pattern: "\"\\$(?:gt|gte|lt|lte|ne|eq|in|nin|all|mod)\"\\s*:\\s*(?:\"\"|null|\\{|\\[)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "nosql"},
	{Pattern: "\"[^\"]+\"\\s*:\\s*\\{\\s*\"\\$(?:ne|eq)\"\\s*:\\s*(?:true|false)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "nosql"},
	{Pattern: "\\[\\$(?:where|gt|gte|lt|lte|ne|eq|regex|in|nin|nor|and|or|not|all|size|exists|type|mod|options|expr|function|elemMatch)\\]", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "nosql"},
	{Pattern: "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|com|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)[\\\"']", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "file_upload"},
	{Pattern: "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:[^ \\\"'][^\\\"']*)?\\.(?:docx|jpeg|pptx|tiff|webm|webp|xlsx|avi|bmp|doc|gif|ico|jpg|mkv|mov|mp3|mp4|odt|pdf|png|ppt|svg|tif|wav|xls)[\\\"']", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "file_upload"},
	{Pattern: "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00|;)[^\\\"']*|\\.)[\\\"']", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "file_upload"},
	{Pattern: "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:(?:\\x00|;)[^\\\"']*|\\.)[\\\"']", Contexts: []string{"header", "query_param", "request_body", "unknown"}, Category: "file_upload"},
	{Pattern: "(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae%e0%80%ae|%25c0%25ae)/", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "path_traversal"},
	{Pattern: "\\{\\{\\s*[^\\}]+(?:system|exec|popen|eval|require|include)\\s*\\}\\}", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "template"},
	{Pattern: "\\{\\%\\s*[^\\%]+(?:system|exec|popen|eval|require|include)\\s*\\%\\}", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "template"},
	{Pattern: "(?i)<%[=#]?[^%]*(?:system|exec|eval|`|Runtime|IO\\.|File\\.|Dir\\.|\\d+\\s*[-+*/]\\s*\\d+)[^%]*%>", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "template"},
	{Pattern: "\\$\\{[^}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|\\d+\\s*[*/%+\\-]\\s*\\d+)[^}]*\\}", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "template"},
	{Pattern: "\\{\\{(?![^\\}]*\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))(?=[^\\}]*(?:@[\\w.]+@|\\b\\w+\\(\\s*\\)|['\\\"]?\\d+['\\\"]?\\s*[*/%+\\-]\\s*['\\\"]?\\d+['\\\"]?))[^\\}]*\\}\\}", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "template"},
	{Pattern: "#\\{(?![^\\}]*\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))(?=[^\\}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|['\\\"]?\\d+['\\\"]?\\s*[*/%+\\-]\\s*['\\\"]?\\d+['\\\"]?))[^\\}]*\\}", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "template"},
	{Pattern: "[\\r\\n][^\\S\\r\\n]*(?:HTTP\\/[0-9.]+|Location:|Set-Cookie:)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "http_split"},
	{Pattern: "\\A[/\\\\]?(?:(?!\\.env(?:\\.\\w+)?(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*\\.env(?:\\.\\w+)?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "sensitive_file"},
	{Pattern: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:\\.env(?:\\.\\w+)?)(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "sensitive_file"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:(?!config)[\\w-])*config[\\w-]*\\.(?:env|yml|yaml|json|toml|ini|xml|conf)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:(?!config)[\\w-])*config[\\w-]*\\.(?:env|yml|yaml|json|toml|ini|xml|conf)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "sensitive_file"},
	{Pattern: "\\A[/\\\\]?(?:(?![\\w.\\-~%]*\\.map(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*\\.map(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "sensitive_file"},
	{Pattern: "\\A[/\\\\]?(?:[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*\\.(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "sensitive_file"},
	{Pattern: "\\A[/\\\\]?(?:(?!\\.(?:git|svn|hg|bzr)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*\\.(?:git|svn|hg|bzr)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "sensitive_file"},
	{Pattern: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:\\.(?:git|svn|hg|bzr))(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "sensitive_file"},
	{Pattern: "\\A[/\\\\]?(?:[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*\\.\\w+~(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "sensitive_file"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)\\.?(?:php)?(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)\\.?(?:php)?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "cms_probing"},
	{Pattern: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)\\.?(?:php)?)(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "cms_probing"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:phpinfo|info|test|php_info)\\.php(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:phpinfo|info|test|php_info)\\.php(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "cms_probing"},
	{Pattern: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:(?:phpinfo|info|test|php_info)\\.php)(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "cms_probing"},
	{Pattern: "\\A[/\\\\]?(?:(?![\\w.\\-~%]*\\.(?:bak|backup|old|orig|save|swp|swo|tmp|temp)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*\\.(?:bak|backup|old|orig|save|swp|swo|tmp|temp)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "cms_probing"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:\\.htaccess|\\.htpasswd|\\.DS_Store|Thumbs\\.db|\\.npmrc|\\.dockerenv|web\\.config)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:\\.htaccess|\\.htpasswd|\\.DS_Store|Thumbs\\.db|\\.npmrc|\\.dockerenv|web\\.config)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "cms_probing"},
	{Pattern: "\\A(?=(?:(?!\\n).)*\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b)\\A(?:(?!\\n).)*[/\\\\](?:(?:\\.htaccess|\\.htpasswd|\\.DS_Store|Thumbs\\.db|\\.npmrc|\\.dockerenv|web\\.config))(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?(?:[/\\\\][\\w.\\-~%]{1,64})?\\b", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "cms_probing"},
	{Pattern: "\\A[/\\\\]?(?:[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*\\.(?:asp|aspx|jsp|jsa|jhtml|shtml|cfm|cgi|do|action|lua|inc|woa|nsf|esp)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\](?:(?!(?:management|config_dump|credentials|system[/\\\\]version|version[/\\\\]system)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:management|config_dump|credentials|system[/\\\\]version|version[/\\\\]system)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\](?:system|version)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:actuator|server-status|telescope)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:actuator|server-status|telescope)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "(?:CSCOE|dana-(?:na|cached)|sslvpn|RDWeb|/owa/|/ecp/|global-protect|ssl-vpn/|svpn/|sonicui|/remote/login|myvpn|vpntunnel|versa/login)", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:geoserver|confluence|nifi|ScadaBR|pandora_console|centreon|kylin|decisioncenter|evox|MagicInfo|metasys|officescan|helpdesk|ignite)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:geoserver|confluence|nifi|ScadaBR|pandora_console|centreon|kylin|decisioncenter|evox|MagicInfo|metasys|officescan|helpdesk|ignite)(?:[.\\-][\\w.\\-~%]*)?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!cgi-(?:bin|mod)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*cgi-(?:bin|mod)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:HNAP1|IPCamDesc\\.xml|SDK/webLanguage)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:HNAP1|IPCamDesc\\.xml|SDK/webLanguage)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:language|languages)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:language|languages)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:readme\\.txt|README\\.md|CHANGELOG|pom\\.xml|build\\.gradle|appsettings\\.json|crossdomain\\.xml)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:readme\\.txt|README\\.md|CHANGELOG|pom\\.xml|build\\.gradle|appsettings\\.json|crossdomain\\.xml)(?:\\.[\\w.\\-~%]*)?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:sap|ise|nidp|cslu|rustfs|developmentserver|fog/management|lms/db|json/login_session|sms_mp|plugin/webs_model|wsman|am_bin)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:sap|ise|nidp|cslu|rustfs|developmentserver|fog/management|lms/db|json/login_session|sms_mp|plugin/webs_model|wsman|am_bin)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "(?:nmaplowercheck|nice\\s+ports|Trinity\\.txt)", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!\\.(?:openclaw|clawdbot)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*\\.(?:openclaw|clawdbot)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:default|inicio|indice|localstart)(?:\\.[\\w.\\-~%]*)?(?:[/\\\\])?(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!inicio\\.html?(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*inicio\\.html?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:\\.streamlit|\\.gpt-pilot|\\.aider|\\.cursor|\\.windsurf|\\.copilot|\\.devcontainer)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:\\.streamlit|\\.gpt-pilot|\\.aider|\\.cursor|\\.windsurf|\\.copilot|\\.devcontainer)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!(?:docker-compose|Dockerfile|Makefile|Vagrantfile|Jenkinsfile|Procfile)(?:\\.ya?ml)?(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*(?:docker-compose|Dockerfile|Makefile|Vagrantfile|Jenkinsfile|Procfile)(?:\\.ya?ml)?(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?![\\w.\\-~%]*(?:secrets?|credentials?)\\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*[\\w.\\-~%]*(?:secrets?|credentials?)\\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!autodiscover(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*autodiscover(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!dns-query(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*dns-query(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "\\A[/\\\\]?(?:(?!\\.git/(?:refs|index|HEAD|objects|logs)(?:[/\\\\]|\\Z))[\\w.\\-~%]+[/\\\\])*\\.git/(?:refs|index|HEAD|objects|logs)(?:[/\\\\][\\w.\\-~%]*)*(?:\\?\\S*)?\\s*\\Z", Contexts: []string{"query_param", "request_body", "unknown", "url_path"}, Category: "recon"},
	{Pattern: "(?:__proto__|constructor)\\s*(?:\\[\\s*[\\\"']prototype[\\\"']\\s*\\]|\\.\\s*prototype)|[\\\"']__proto__[\\\"']\\s*:", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "proto_pollution"},
	{Pattern: "__proto__\\s*(?:\\[|\\.)|\\[\\s*[\\\"']?__proto__[\\\"']?\\s*\\]|constructor\\s*\\[\\s*[\\\"']?prototype[\\\"']?\\s*\\]|\\[\\s*[\\\"']?constructor[\\\"']?\\s*\\]\\s*\\[\\s*[\\\"']?prototype[\\\"']?\\s*\\]", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "proto_pollution"},
	{Pattern: "Object\\.prototype\\.[A-Za-z_$][\\w$]*\\s*=(?!=)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "proto_pollution"},
	{Pattern: "\\b(?:Object|Reflect)\\.setPrototypeOf\\s*\\(", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "proto_pollution"},
	{Pattern: "System\\.Diagnostics\\.Process\\.Start\\s*\\(|System\\.Reflection\\.|Assembly\\.Load\\s*\\(", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "code_injection"},
	{Pattern: "(?-i:\\bgetattr\\(\\s*(?:__import__\\(\\s*['\\\"](?:os|subprocess|builtins|importlib)['\\\"]\\s*\\)|\\b(?:os|subprocess|builtins|importlib)\\b)\\s*,\\s*['\\\"](?:system|popen|exec|eval|call|run|Popen|check_output|check_call)['\\\"]\\s*\\)\\s*\\()", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "code_injection"},
	{Pattern: "(?-i:\\bvars\\(\\s*(?:__import__\\(\\s*['\\\"](?:os|subprocess|builtins|importlib)['\\\"]\\s*\\)|\\b(?:os|subprocess|builtins|importlib)\\b)\\s*\\)\\s*\\[\\s*['\\\"](?:system|popen|exec|eval|call|run|Popen|check_output|check_call)['\\\"]\\s*\\]\\s*\\()", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "code_injection"},
	{Pattern: "(?<![A-Za-z0-9+/])(?-i:rO0AB)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "(?<![A-Za-z0-9+/])(?-i:AAEAAAD)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "(?<![A-Za-z0-9+/])(?-i:gA[SW]V)", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "(?<![A-Za-z0-9+/])(?-i:BAh[Jv7bV])", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "cos\\n", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "c__builtin__", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "csubprocess", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "cposix", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "(c[A-Za-z_][A-Za-z0-9_]{0,100}(?:\\.[A-Za-z_][A-Za-z0-9_]{0,100}){0,20}\\n[A-Za-z_][A-Za-z0-9_]{0,100}\\n)[^ \\t]{0,100}?[Rb]", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "O:\\d+:\"", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "C:\\d+:\"", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "E:\\d+:\"", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
	{Pattern: "<ObjectDataProvider\\b", Contexts: []string{"header", "query_param", "request_body", "unknown", "url_path"}, Category: "deserialization"},
}

// reconOptionalSeparatorAnchor is the top-level path prefix (\A[/\\]?) that
// opens every whole-value recon row whose leading path separator is
// OPTIONAL: outside a URL path those rows match bare words such as "default"
// or "README.md", not only probe paths. Rows anchored on a REQUIRED
// separator start with \A[/\\] (no trailing question mark) and are excluded
// by the prefix check, as are recon rows with no \A anchor at all.
// Mirrors Python's RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES derivation
// (guard_core/handlers/_suspatterns_pattern_table.py, upstream issue #115).
const reconOptionalSeparatorAnchor = `\A[/\\]?`

// reconOptionalSeparatorPatternSources is derived from patternTable with the
// same rule as the Python engine, so recon rows added later are picked up by
// the leading-separator gate without a hand-maintained list.
var reconOptionalSeparatorPatternSources = func() map[string]bool {
	sources := make(map[string]bool)
	for _, def := range patternTable {
		if def.Category == "recon" && strings.HasPrefix(def.Pattern, reconOptionalSeparatorAnchor) {
			sources[def.Pattern] = true
		}
	}
	return sources
}()

// reconRawViewPatternSources mirrors DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES
// from guard_core/handlers/_suspatterns_pattern_table.py: every recon row is
// additionally scanned against the signal-preserving raw view. The processed
// views fold LDAP hex escapes ("\de" -> U+00DE) before the pattern tables
// run, so separator-prefixed probes such as "\default" or "\report.asp"
// never reach a recon row there; the raw view keeps them intact and the
// leading-separator gate still decides which matches are probes, so bare
// words stay innocent exactly as on the processed views.
var reconRawViewPatternSources = func() map[string]bool {
	sources := make(map[string]bool)
	for _, def := range patternTable {
		if def.Category == "recon" {
			sources[def.Pattern] = true
		}
	}
	return sources
}()

var rawViewSources = map[string]bool{
	"#\\{(?![^\\}]*\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))(?=[^\\}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|['\\\"]?\\d+['\\\"]?\\s*[*/%+\\-]\\s*['\\\"]?\\d+['\\\"]?))[^\\}]*\\}": true,
	"'\\s*(?:[\\);]+\\s*)?--|'[\\);]*#(?:\\n|\\Z)":                                          true,
	"(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae%e0%80%ae|%25c0%25ae)/": true,
	"(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00|;)[^\\\"']*|\\.)[\\\"']":                                                                                 true,
	"(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:[^ \\\"'][^\\\"']*)?\\.(?:docx|jpeg|pptx|tiff|webm|webp|xlsx|avi|bmp|doc|gif|ico|jpg|mkv|mov|mp3|mp4|odt|pdf|png|ppt|svg|tif|wav|xls)[\\\"']": true,
	"(?<![A-Za-z0-9+/])(?-i:AAEAAAD)":    true,
	"(?<![A-Za-z0-9+/])(?-i:BAh[Jv7bV])": true,
	"(?<![A-Za-z0-9+/])(?-i:gA[SW]V)":    true,
	"(?<![A-Za-z0-9+/])(?-i:rO0AB)":      true,
	"(?i)\\bORDER\\s+BY\\s+\\d+\\s*(?:--|#|;|\\)|,|/\\*|\\Z)|(?<=[=?&])ORDER\\s+BY\\s+\\d+\\s*\\n":                                  true,
	"(c[A-Za-z_][A-Za-z0-9_]{0,100}(?:\\.[A-Za-z_][A-Za-z0-9_]{0,100}){0,20}\\n[A-Za-z_][A-Za-z0-9_]{0,100}\\n)[^ \\t]{0,100}?[Rb]": true,
	"[\\r\\n][^\\S\\r\\n]*(?:HTTP\\/[0-9.]+|Location:|Set-Cookie:)":                                                                 true,
	"[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)":                                                  true,
	"\\*\\)\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)":                                                                               true,
	"cos\\n": true,
	"j[\\t\\r\\n]*a[\\t\\r\\n]*v[\\t\\r\\n]*a[\\t\\r\\n]*s[\\t\\r\\n]*c[\\t\\r\\n]*r[\\t\\r\\n]*i[\\t\\r\\n]*p[\\t\\r\\n]*t[\\t\\r\\n]*:\\s*[^\\s]+": true,
}

var urlDecodedViewSources = map[string]bool{
	"(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|aspx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cgi|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py|rb|sh|ws)(?![A-Za-z0-9])(?:(?:\\x00|;)[^\\\"']*|\\.)[\\\"']": true,
	"(?i)(?:['\\\")\\d]|/\\*)\\s{0,3}\\bORDER\\s+BY\\s+\\d+|\\bORDER\\s+BY\\s+\\d+\\s*(?:--|#|/\\*)": true,
	"[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+\\x00":                                                   true,
	"\\*\\)\\)+\\x00": true,
	"\\A(?:(?!\\n).)*(?:boot\\.ini|win\\.ini|system\\.ini|config\\.sys)(?:[&#;,\\\"'<>]|\\s*\\Z)":                                          true,
	"\\A(?:(?!\\n).)*etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\\.cnf|ssh/ssh_config)(?:[&#;,\\\"'<>]|\\s*\\Z)":                  true,
	"\\A(?:(?!\\n).)*proc/self/environ(?:[&#;,\\\"'<>]|\\s*\\Z)":                                                                           true,
	"\\A(?:(?!\\n).)*var/log/[^\\s/]+(?:[&#;,\\\"'<>]|\\s*\\Z)":                                                                            true,
	"\\n[^\\S\\r\\n]*(?:[^=\\s;|&]+=[^\\s;|&]+\\s+)*(?:/?(?:[\\w.-]+/)*env\\s+)?/?(?:[\\w.-]+/)*(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-c\\b": true,
}

var scanWindowBounds = map[string][][2]string{

	"<script[^>]*>[^<]*<\\/script\\s*>": {{"<script", "<\\/script\\s*>"}},

	"(?:<[A-Za-z/][^<>]*style\\s*=\\s{0,20}[\\\"']?[^<>\\\"']*(?:expression|behavior|url)\\s*\\([^)]*\\))": {{"<[A-Za-z/][^<>]*style\\s*=", "\\)"}},

	"(?:<object[^>]*>[\\s\\S]*<\\/object\\s*>)": {{"<object", "<\\/object\\s*>"}},

	"(?:<embed[^>]*>[\\s\\S]*<\\/embed\\s*>)": {{"<embed", "<\\/embed\\s*>"}},

	"(?:<applet[^>]*>[\\s\\S]*<\\/applet\\s*>)": {{"<applet", "<\\/applet\\s*>"}},

	"\\.\\.;[^/\\\\]*[/\\\\]": {{"\\.\\.;", "[/\\\\]"}},

	"=(?:https?|ftp):\\/\\/[^\\s'\\\"<>]+\\/[^\\s'\\\"<>\\/]*\\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)(?![a-zA-Z0-9])": {{"=(?:https?|ftp):\\/\\/", "\\.(?:phtml|php\\d*|phar|jsp|aspx?|pl|py|txt|inc)[a-zA-Z0-9]*"}},

	"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>": {{"<!(?:ENTITY|DOCTYPE)", ">"}},

	"(?:<!\\[CDATA\\[.*?\\]\\]>)": {{"<!\\[CDATA\\[", "\\]\\]>"}},

	"<!DOCTYPE[^>\\[]*\\[[\\s\\S]*?<!ENTITY": {{"<!DOCTYPE", "<!ENTITY"}},
}

var weightOverrides = map[string]float64{
	"(?i)\\bSELECT\\b(?:(?!\\bSELECT\\b)[\\w\\s,\\*().])*?\\bFROM\\b": 0.5,
	"(?i)SELECT\\s+\\*": 0.5,
	"(?i)\\bWHERE\\s+[\\w.\"]+\\s*(?:=|<|>|<=|>=|LIKE|IN)\\b": 0.5,
}

var uploadDangerousExts = map[string]bool{
	"asa":   true,
	"asax":  true,
	"ascx":  true,
	"ashx":  true,
	"asmx":  true,
	"asp":   true,
	"aspx":  true,
	"bash":  true,
	"bat":   true,
	"cer":   true,
	"cfc":   true,
	"cfm":   true,
	"cgi":   true,
	"cmd":   true,
	"com":   true,
	"exe":   true,
	"hta":   true,
	"js":    true,
	"jsp":   true,
	"jspx":  true,
	"msi":   true,
	"phar":  true,
	"phps":  true,
	"pht":   true,
	"phtml": true,
	"pl":    true,
	"py":    true,
	"rb":    true,
	"sh":    true,
	"shtml": true,
	"vbe":   true,
	"vbs":   true,
	"war":   true,
	"ws":    true,
	"wsf":   true,
}

var uploadDoubleExts = map[string]bool{
	"asa":   true,
	"asax":  true,
	"ascx":  true,
	"ashx":  true,
	"asmx":  true,
	"asp":   true,
	"aspx":  true,
	"bash":  true,
	"bat":   true,
	"cer":   true,
	"cfc":   true,
	"cfm":   true,
	"cgi":   true,
	"cmd":   true,
	"exe":   true,
	"hta":   true,
	"js":    true,
	"jsp":   true,
	"jspx":  true,
	"msi":   true,
	"phar":  true,
	"phps":  true,
	"pht":   true,
	"phtml": true,
	"pl":    true,
	"py":    true,
	"rb":    true,
	"sh":    true,
	"shtml": true,
	"vbe":   true,
	"vbs":   true,
	"war":   true,
	"ws":    true,
	"wsf":   true,
}

var uploadBenignExts = map[string]bool{
	"avi":  true,
	"bmp":  true,
	"doc":  true,
	"docx": true,
	"gif":  true,
	"ico":  true,
	"jpeg": true,
	"jpg":  true,
	"mkv":  true,
	"mov":  true,
	"mp3":  true,
	"mp4":  true,
	"odt":  true,
	"pdf":  true,
	"png":  true,
	"ppt":  true,
	"pptx": true,
	"svg":  true,
	"tif":  true,
	"tiff": true,
	"wav":  true,
	"webm": true,
	"webp": true,
	"xls":  true,
	"xlsx": true,
}

func extAlternation(exts map[string]bool, phpPrefix bool) string {
	keys := make([]string, 0, len(exts))
	for k := range exts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	parts := make([]string, 0, len(keys)+1)
	if phpPrefix {
		parts = append(parts, `php\d*`)
	}
	for _, k := range keys {
		parts = append(parts, goQuoteMeta(k))
	}
	return strings.Join(parts, "|")
}

var fileUploadDangerousAlt = extAlternation(uploadDangerousExts, true)
var fileUploadDoubleAlt = extAlternation(uploadDoubleExts, true)
var fileUploadBenignAlt = extAlternation(uploadBenignExts, false)

func goQuoteMeta(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$', '/':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
