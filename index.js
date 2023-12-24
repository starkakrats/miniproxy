//NOTE: miniProxy IS NO LONGER MAINTAINED AS OF APRIL 26th, 2020.
//IF YOU USE IT, YOU DO SO ENTIRELY AT YOUR OWN RISK.
//More information is available at <https://github.com/joshdick/miniProxy>.
//miniProxy - A simple PHP web proxy. <https://github.com/joshdick/miniProxy>
//Written and maintained by Joshua Dick <http://joshdick.net>.
//miniProxy is licensed under the GNU GPL v3 <https://www.gnu.org/licenses/gpl-3.0.html>.
// START CONFIGURATION *****************************
//NOTE: If a given URL matches a pattern in both $whitelistPatterns and $blacklistPatterns,
//that URL will be treated as blacklisted.
//To allow proxying any URL, set $whitelistPatterns to an empty array (the default).
//To only allow proxying of specific URLs (whitelist), add corresponding regular expressions
//to the $whitelistPatterns array. To prevent possible abuse, enter the narrowest/most-specific patterns possible.
//You can optionally use the "getHostnamePattern()" helper function to build a regular expression that
//matches all URLs for a given hostname.
//To disallow proxying of specific URLs (blacklist), add corresponding regular expressions
//to the $blacklistPatterns array. To prevent possible abuse, enter the broadest/least-specific patterns possible.
//You can optionally use the "getHostnamePattern()" helper function to build a regular expression that
//matches all URLs for a given hostname.
//To enable CORS (cross-origin resource sharing) for proxied sites, set $forceCORS to true.
//Set to false to allow sites on the local network (where miniProxy is running) to be proxied.
//Set to false to report the client machine's IP address to proxied sites via the HTTP `x-forwarded-for` header.
//Setting to false may improve compatibility with some sites, but also exposes more information about end users to proxied sites.
//Start/default URL that that will be proxied when miniProxy is first loaded in a browser/accessed directly with no URL to proxy.
//If empty, miniProxy will show its own landing page.
//When no $startURL is configured above, miniProxy will show its own landing page with a URL form field
//and the configured example URL. The example URL appears in the instructional text on the miniProxy landing page,
//and is proxied when pressing the 'Proxy It!' button on the landing page if its URL form is left blank.
// END CONFIGURATION *****************************
//Helper function for use inside $whitelistPatterns/$blacklistPatterns.
//Returns a regex that matches all HTTP[S] URLs for a given hostname.
//Helper function that determines whether to allow proxying of a given URL.
//Helper function used to removes/unset keys from an associative array using case insensitive matching
//Use HTTP_HOST to support client-configured DNS (instead of SERVER_NAME), but remove the port if one is present
//Makes an HTTP request via cURL, using request data that was passed directly to this script.
//Converts relative URLs to absolute ones, given a base URL.
//Modified version of code found at http://nashruddin.com/PHP_Script_for_Converting_Relative_to_Absolute_URL
//Proxify contents of url() references in blocks of CSS text.
//Proxify "srcset" attributes (normally associated with <img> tags.)
//Extract and sanitize the requested URL, handling cases where forms have been rewritten to point to the proxy.
//If CURLOPT_FOLLOWLOCATION landed the proxy at a diferent URL than
//what was requested, explicitly redirect the proxy there.
//cURL can make multiple requests internally (for example, if CURLOPT_FOLLOWLOCATION is enabled), and reports
//headers for every request it makes. Only proxy the last set of received response headers,
//corresponding to the final request made by cURL for any given call to makeRequest().
//Prevent robots from indexing proxified pages
var whitelistPatterns = Array();
var blacklistPatterns = Array();
var forceCORS = false;
var disallowLocal = true;
var anonymize = true;
var startURL = "";
var landingExampleURL = "https://example.net";
ob_start("ob_gzhandler");

if (version_compare(PHP_VERSION, "5.4.7", "<")) {
  throw die("miniProxy requires PHP version 5.4.7 or later.");
}

var requiredExtensions = ["curl", "mbstring", "xml"];

for (var requiredExtension of Object.values(requiredExtensions)) {
  if (!extension_loaded(requiredExtension)) {
    throw die("miniProxy requires PHP's \"" + requiredExtension + "\" extension. Please install/enable it on your server and try again.");
  }
}

function getHostnamePattern(hostname) {
  var escapedHostname = str_replace(".", "\\.", hostname);
  return "@^https?://([a-z0-9-]+\\.)*" + escapedHostname + "@i";
};

function isValidURL(url) //Validates a URL against the whitelist.
//Validates a URL against the blacklist.
{
  function passesWhitelist(url) {
    if (GLOBALS.whitelistPatterns.length === 0) return true;

    for (var pattern of Object.values(GLOBALS.whitelistPatterns)) {
      if (preg_match(pattern, url)) {
        return true;
      }
    }

    return false;
  };

  function passesBlacklist(url) {
    for (var pattern of Object.values(GLOBALS.blacklistPatterns)) {
      if (preg_match(pattern, url)) {
        return false;
      }
    }

    return true;
  };

  function isLocal(url) //First, generate a list of IP addresses that correspond to the requested URL.
  {
    var ips = Array();
    var host = parse_url(url, PHP_URL_HOST);

    if (filter_var(host, FILTER_VALIDATE_IP)) //The supplied host is already a valid IP address.
      {
        ips = [host];
      } else //The host is not a valid IP address; attempt to resolve it to one.
      {
        var dnsResult = dns_get_record(host, DNS_A + DNS_AAAA);
        ips = dnsResult.map(dnsRecord => {
          return dnsRecord.type == "A" ? dnsRecord.ip : dnsRecord.ipv6;
        });
      }

    for (var ip of Object.values(ips)) //Determine whether any of the IPs are in the private or reserved range.
    {
      if (!filter_var(ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return true;
      }
    }

    return false;
  };

  return passesWhitelist(url) && passesBlacklist(url) && (GLOBALS.disallowLocal ? !isLocal(url) : true);
};

function removeKeys(assoc, keys2remove) {
  var keys = Object.keys(assoc);
  var map = Array();
  var removedKeys = Array();

  for (var key of Object.values(keys)) {
    map[key.toLowerCase()] = key;
  }

  for (var key of Object.values(keys2remove)) {
    var key = key.toLowerCase();

    if (undefined !== map[key]) {
      delete assoc[map[key]];
      removedKeys.push(map[key]);
    }
  }

  return removedKeys;
};

if (!("function" === typeof getallheaders)) //Adapted from http://www.php.net/manual/en/function.getallheaders.php#99814
  {
    function getallheaders() {
      var result = Array();

      for (var key in _SERVER) {
        var value = _SERVER[key];

        if (key.substr(0, 5) == "HTTP_") {
          var key = str_replace(" ", "-", ucwords(str_replace("_", " ", key.substr(5)).toLowerCase()));
          result[key] = value;
        }
      }

      return result;
    };
  }

var usingDefaultPort = !(undefined !== _SERVER.HTTPS) && _SERVER.SERVER_PORT === 80 || undefined !== _SERVER.HTTPS && _SERVER.SERVER_PORT === 443;
var prefixPort = usingDefaultPort ? "" : ":" + _SERVER.SERVER_PORT;
var prefixHost = _SERVER.HTTP_HOST;
prefixHost = strpos(prefixHost, ":") ? _SERVER.HTTP_HOST.split(":", -1).join(":") : prefixHost;
const PROXY_PREFIX = "http" + (undefined !== _SERVER.HTTPS ? "s" : "") + "://" + prefixHost + prefixPort + _SERVER.SCRIPT_NAME + "?";

function makeRequest(url) //Tell cURL to make the request using the brower's user-agent if there is one, or a fallback user-agent otherwise.
//Get ready to proxy the browser's request headers...
//...but let cURL set some headers on its own.
//Transform the associative array from getallheaders() into an
//indexed array of header strings to be passed to cURL.
//Proxy any received GET/POST/PUT data.
//Set the request URL.
//Make the request.
//Setting CURLOPT_HEADER to true above forces the response headers and body
//to be output together--separate them.
{
  if (!("anonymize" in global)) anonymize = undefined;
  var user_agent = _SERVER.HTTP_USER_AGENT;

  if (!user_agent) {
    user_agent = "Mozilla/5.0 (compatible; miniProxy)";
  }

  var ch = curl_init();
  curl_setopt(ch, CURLOPT_USERAGENT, user_agent);
  var browserRequestHeaders = getallheaders();
  var removedHeaders = removeKeys(browserRequestHeaders, ["Accept-Encoding", "Content-Length", "Host", "Origin"]);
  removedHeaders = removedHeaders.map("strtolower");
  curl_setopt(ch, CURLOPT_ENCODING, "");
  var curlRequestHeaders = Array();

  for (var name in browserRequestHeaders) {
    var value = browserRequestHeaders[name];
    curlRequestHeaders.push(name + ": " + value);
  }

  if (!anonymize) {
    curlRequestHeaders.push("X-Forwarded-For: " + _SERVER.REMOTE_ADDR);
  }

  if (-1 !== removedHeaders.indexOf("origin")) {
    var urlParts = parse_url(url);
    var port = urlParts.port;
    curlRequestHeaders.push("Origin: " + urlParts.scheme + "://" + urlParts.host + (!port ? "" : ":" + port));
  }

  curl_setopt(ch, CURLOPT_HTTPHEADER, curlRequestHeaders);

  switch (_SERVER.REQUEST_METHOD) {
    case "POST":
      curl_setopt(ch, CURLOPT_POST, true);
      var postData = Array();
      parse_str(file_get_contents("php://input"), postData);

      if (undefined !== postData.miniProxyFormAction) {
        delete postData.miniProxyFormAction;
      }

      curl_setopt(ch, CURLOPT_POSTFIELDS, http_build_query(postData));
      break;

    case "PUT":
      curl_setopt(ch, CURLOPT_PUT, true);
      curl_setopt(ch, CURLOPT_INFILE, fopen("php://input", "r"));
      break;
  }

  curl_setopt(ch, CURLOPT_HEADER, true);
  curl_setopt(ch, CURLOPT_FOLLOWLOCATION, true);
  curl_setopt(ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt(ch, CURLOPT_URL, url);
  var response = curl_exec(ch);
  var responseInfo = curl_getinfo(ch);
  var headerSize = curl_getinfo(ch, CURLINFO_HEADER_SIZE);
  curl_close(ch);
  var responseHeaders = response.substr(0, headerSize);
  var responseBody = response.substr(headerSize);
  return {
    headers: responseHeaders,
    body: responseBody,
    responseInfo: responseInfo
  };
};

function rel2abs(rel, base) //Parse base URL and convert to local variables: $scheme, $host, $path
//Remove non-directory element from path
//Dirty absolute URL
//Replace '//' or '/./' or '/foo/../' with '/'
//Absolute URL is ready.
{
  if (!rel) rel = ".";
  if (parse_url(rel, PHP_URL_SCHEME) != "" || strpos(rel, "//") === 0) return rel;
  if (rel[0] == "#" || rel[0] == "?") return base + rel;
  extract(parse_url(base));
  var path = undefined !== path ? path.replace(/\/[^\/]*$/g, "") : "/";
  if (rel[0] == "/") path = "";
  var port = undefined !== port && port != 80 ? ":" + port : "";
  var auth = "";

  if (undefined !== user) {
    auth = user;

    if (undefined !== pass) {
      auth += ":" + pass;
    }

    auth += "@";
  }

  var abs = `${auth}${host}${port}${path}/${rel}`;

  for (var n = 1; n > 0; abs = preg_replace(["#(/\\.?/)#", "#/(?!\\.\\.)[^/]+/\\.\\./#"], "/", abs, -1, n)) {}

  return scheme + "://" + abs;
};

function proxifyCSS(css, baseURL) //Add a "url()" wrapper to any CSS @import rules that only specify a URL without the wrapper,
//so that they're proxified when searching for "url()" wrappers below.
{
  var sourceLines = css.split("\n");
  var normalizedLines = Array();

  for (var line of Object.values(sourceLines)) {
    if (preg_match("/@import\\s+url/i", line)) {
      normalizedLines.push(line);
    } else {
      normalizedLines.push(line.replace(/(@import\s+)([^;\s]+)([\s;])/gi, matches => {
        return matches[1] + "url(" + matches[2] + ")" + matches[3];
      }));
    }
  }

  var normalizedCSS = normalizedLines.join("\n");
  return normalizedCSS.replace(/url\((.*?)\)/gi, matches => //Remove any surrounding single or double quotes from the URL so it can be passed to rel2abs - the quotes are optional in CSS
  //Assume that if there is a leading quote then there should be a trailing quote, so just use trim() to remove them
  {
    var url = matches[1];

    if (strpos(url, "'") === 0) {
      url = url.replace(/^'*|'*$/g, "");
    }

    if (strpos(url, "\"") === 0) {
      url = url.replace(/^"*|"*$/g, "");
    }

    if (stripos(url, "data:") === 0) return "url(" + url + ")";
    return "url(" + PROXY_PREFIX + rel2abs(url, baseURL) + ")";
  });
};

function proxifySrcset(srcset, baseURL) //Split all contents by comma and trim each value
//Recombine the sources into a single "srcset"
{
  var sources = srcset.split(",").map("trim");
  var proxifiedSources = sources.map(source => //Split by last space and trim
  //First component of the split source string should be an image URL; proxify it
  //Recombine the components into a single source
  {
    var components = str_split(source, strrpos(source, " ")).map("trim");
    components[0] = PROXY_PREFIX + rel2abs(components[0].replace(/^[\/]*/, ""), baseURL);
    return " ".join(components);
  });
  var proxifiedSrcset = proxifiedSources.join(", ");
  return proxifiedSrcset;
};

if (undefined !== _POST.miniProxyFormAction) {
  var url = _POST.miniProxyFormAction;
  delete _POST.miniProxyFormAction;
} else //If the miniProxyFormAction field appears in the query string, make $url start with its value, and rebuild the the query string without it.
  {
    var queryParams = Array();
    parse_str(_SERVER.QUERY_STRING, queryParams);

    if (undefined !== queryParams.miniProxyFormAction) {
      var formAction = queryParams.miniProxyFormAction;
      delete queryParams.miniProxyFormAction;
      url = formAction + "?" + http_build_query(queryParams);
    } else {
      url = _SERVER.REQUEST_URI.substr(_SERVER.SCRIPT_NAME.length + 1);
    }
  }

if (!url) {
  if (!startURL) {
    throw die("<html><head><title>miniProxy</title></head><body><h1>Welcome to miniProxy!</h1>miniProxy can be directly invoked like this: <a href=\"" + PROXY_PREFIX + landingExampleURL + "\">" + PROXY_PREFIX + landingExampleURL + "</a><br /><br />Or, you can simply enter a URL below:<br /><br /><form onsubmit=\"if (document.getElementById('site').value) { window.location.href='" + PROXY_PREFIX + "' + document.getElementById('site').value; return false; } else { window.location.href='" + PROXY_PREFIX + landingExampleURL + "'; return false; }\" autocomplete=\"off\"><input id=\"site\" type=\"text\" size=\"50\" /><input type=\"submit\" value=\"Proxy It!\" /></form></body></html>");
  } else {
    url = startURL;
  }
} else if (strpos(url, ":/") !== strpos(url, "://")) //Work around the fact that some web servers (e.g. IIS 8.5) change double slashes appearing in the URL to a single slash.
  //See https://github.com/joshdick/miniProxy/pull/14
  {
    var pos = strpos(url, ":/");
    url = substr_replace(url, "://", pos, ":/".length);
  }

var scheme = parse_url(url, PHP_URL_SCHEME);

if (!scheme) {
  if (strpos(url, "//") === 0) //Assume that any supplied URLs starting with // are HTTP URLs.
    {
      url = "http:" + url;
    } else //Assume that any supplied URLs without a scheme (just a host) are HTTP URLs.
    {
      url = "http://" + url;
    }
} else if (!preg_match("/^https?$/i", scheme)) {
  throw die("Error: Detected a \"" + scheme + "\" URL. miniProxy exclusively supports http[s] URLs.");
}

if (!isValidURL(url)) {
  throw die("Error: The requested URL was disallowed by the server administrator.");
}

var response = makeRequest(url);
var rawResponseHeaders = response.headers;
var responseBody = response.body;
var responseInfo = response.responseInfo;
var responseURL = responseInfo.url;

if (responseURL !== url) {
  header("Location: " + PROXY_PREFIX + responseURL, true);
  throw die(0);
}

var header_blacklist_pattern = "/^Content-Length|^Transfer-Encoding|^Content-Encoding.*gzip/i";
var responseHeaderBlocks = rawResponseHeaders.split("\r\n\r\n").filter();
var lastHeaderBlock = end(responseHeaderBlocks);
var headerLines = lastHeaderBlock.split("\r\n");

for (var header of Object.values(headerLines)) {
  var header = header.trim();

  if (!preg_match(header_blacklist_pattern, header)) {
    header(header, false);
  }
}

header("X-Robots-Tag: noindex, nofollow", true);

if (forceCORS) //This logic is based on code found at: http://stackoverflow.com/a/9866124/278810
  //CORS headers sent below may conflict with CORS headers from the original response,
  //so these headers are sent after the original response headers to ensure their values
  //are the ones that actually end up getting sent to the browser.
  //Explicit [ $replace = true ] is used for these headers even though this is PHP's default behavior.
  //Allow access from any origin.
  //Handle CORS headers received during OPTIONS requests.
  {
    header("Access-Control-Allow-Origin: *", true);
    header("Access-Control-Allow-Credentials: true", true);

    if (_SERVER.REQUEST_METHOD == "OPTIONS") {
      if (undefined !== _SERVER.HTTP_ACCESS_CONTROL_REQUEST_METHOD) {
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS", true);
      }

      if (undefined !== _SERVER.HTTP_ACCESS_CONTROL_REQUEST_HEADERS) {
        header(`Access-Control-Allow-Headers: ${_SERVER.HTTP_ACCESS_CONTROL_REQUEST_HEADERS}`, true);
      }

      throw die(0);
    }
  }

var contentType = "";
if (undefined !== responseInfo.content_type) contentType = responseInfo.content_type;

if (stripos(contentType, "text/html") !== false) //Attempt to normalize character encoding.
  //Rewrite forms so that their actions point back to the proxy.
  //Proxify <meta> tags with an 'http-equiv="refresh"' attribute.
  //Profixy <style> tags.
  //Proxify tags with a "style" attribute.
  //Proxify "srcset" attributes in <img> tags.
  //Proxify any of these attributes appearing in any tag.
  //Attempt to force AJAX requests to be made through the proxy by
  //wrapping window.XMLHttpRequest.prototype.open in order to make
  //all request URLs absolute and point back to the proxy.
  //The rel2abs() JavaScript function serves the same purpose as the server-side one in this file,
  //but is used in the browser to ensure all AJAX request URLs are absolute and not relative.
  //Uses code from these sources:
  //http://stackoverflow.com/questions/7775767/javascript-overriding-xmlhttprequest-open
  //https://gist.github.com/1088850
  //TODO: This is obviously only useful for browsers that use XMLHttpRequest but
  //it's better than nothing.
  //Only bother trying to apply this hack if the DOM has a <head> or <body> element;
  //insert some JavaScript at the top of whichever is available first.
  //Protects against cases where the server sends a Content-Type of "text/html" when
  //what's coming back is most likely not actually HTML.
  //TODO: Do this check before attempting to do any sort of DOM parsing?
  {
    var detectedEncoding = mb_detect_encoding(responseBody, "UTF-8, ISO-8859-1");

    if (detectedEncoding) {
      responseBody = mb_convert_encoding(responseBody, "HTML-ENTITIES", detectedEncoding);
    }

    var doc = new DomDocument();
    doc.loadHTML(responseBody);
    var xpath = new DOMXPath(doc);

    for (var form of Object.values(xpath.query("//form"))) //If the form doesn't have an action, the action is the page itself.
    //Otherwise, change an existing action to an absolute version.
    //Rewrite the form action to point back at the proxy.
    //Add a hidden form field that the proxy can later use to retreive the original form action.
    {
      var method = form.getAttribute("method");
      var action = form.getAttribute("action");
      action = !action ? url : rel2abs(action, url);
      form.setAttribute("action", PROXY_PREFIX.replace(/?*$/, ""));
      var actionInput = doc.createDocumentFragment();
      actionInput.appendXML("<input type=\"hidden\" name=\"miniProxyFormAction\" value=\"" + htmlspecialchars(action) + "\" />");
      form.appendChild(actionInput);
    }

    for (var element of Object.values(xpath.query("//meta[@http-equiv]"))) {
      if (strcasecmp(element.getAttribute("http-equiv"), "refresh") === 0) {
        var content = element.getAttribute("content");

        if (!!content) {
          var splitContent = preg_split("/=/", content);

          if (undefined !== splitContent[1]) {
            element.setAttribute("content", splitContent[0] + "=" + PROXY_PREFIX + rel2abs(splitContent[1], url));
          }
        }
      }
    }

    for (var style of Object.values(xpath.query("//style"))) {
      style.nodeValue = proxifyCSS(style.nodeValue, url);
    }

    for (var element of Object.values(xpath.query("//*[@style]"))) {
      element.setAttribute("style", proxifyCSS(element.getAttribute("style"), url));
    }

    for (var element of Object.values(xpath.query("//img[@srcset]"))) {
      element.setAttribute("srcset", proxifySrcset(element.getAttribute("srcset"), url));
    }

    var proxifyAttributes = ["href", "src"];

    for (var attrName of Object.values(proxifyAttributes)) {
      for (var element of Object.values(xpath.query("//*[@" + attrName + "]"))) //For every element with the given attribute...
      {
        var attrContent = element.getAttribute(attrName);
        if (attrName == "href" && preg_match("/^(about|javascript|magnet|mailto):|#/i", attrContent)) continue;
        if (attrName == "src" && preg_match("/^(data):/i", attrContent)) continue;
        attrContent = rel2abs(attrContent, url);
        attrContent = PROXY_PREFIX + attrContent;
        element.setAttribute(attrName, attrContent);
      }
    }

    var head = xpath.query("//head").item(0);
    var body = xpath.query("//body").item(0);
    var prependElem = head != undefined ? head : body;

    if (prependElem != undefined) {
      var scriptElem = doc.createElement("script", "(function() {\n\n        if (window.XMLHttpRequest) {\n\n          function parseURI(url) {\n            var m = String(url).replace(/^\\s+|\\s+$/g, \"\").match(/^([^:\\/?#]+:)?(\\/\\/(?:[^:@]*(?::[^:@]*)?@)?(([^:\\/?#]*)(?::(\\d*))?))?([^?#]*)(\\?[^#]*)?(#[\\s\\S]*)?/);\n            // authority = \"//\" + user + \":\" + pass \"@\" + hostname + \":\" port\n            return (m ? {\n              href : m[0] || \"\",\n              protocol : m[1] || \"\",\n              authority: m[2] || \"\",\n              host : m[3] || \"\",\n              hostname : m[4] || \"\",\n              port : m[5] || \"\",\n              pathname : m[6] || \"\",\n              search : m[7] || \"\",\n              hash : m[8] || \"\"\n            } : null);\n          }\n\n          function rel2abs(base, href) { // RFC 3986\n\n            function removeDotSegments(input) {\n              var output = [];\n              input.replace(/^(\\.\\.?(\\/|$))+/, \"\")\n                .replace(/\\/(\\.(\\/|$))+/g, \"/\")\n                .replace(/\\/\\.\\.$/, \"/../\")\n                .replace(/\\/?[^\\/]*/g, function (p) {\n                  if (p === \"/..\") {\n                    output.pop();\n                  } else {\n                    output.push(p);\n                  }\n                });\n              return output.join(\"\").replace(/^\\//, input.charAt(0) === \"/\" ? \"/\" : \"\");\n            }\n\n            href = parseURI(href || \"\");\n            base = parseURI(base || \"\");\n\n            return !href || !base ? null : (href.protocol || base.protocol) +\n            (href.protocol || href.authority ? href.authority : base.authority) +\n            removeDotSegments(href.protocol || href.authority || href.pathname.charAt(0) === \"/\" ? href.pathname : (href.pathname ? ((base.authority && !base.pathname ? \"/\" : \"\") + base.pathname.slice(0, base.pathname.lastIndexOf(\"/\") + 1) + href.pathname) : base.pathname)) +\n            (href.protocol || href.authority || href.pathname ? href.search : (href.search || base.search)) +\n            href.hash;\n\n          }\n\n          var proxied = window.XMLHttpRequest.prototype.open;\n          window.XMLHttpRequest.prototype.open = function() {\n              if (arguments[1] !== null && arguments[1] !== undefined) {\n                var url = arguments[1];\n                url = rel2abs(\"" + url + "\", url);\n                if (url.indexOf(\"" + PROXY_PREFIX + "\") == -1) {\n                  url = \"" + PROXY_PREFIX + "\" + url;\n                }\n                arguments[1] = url;\n              }\n              return proxied.apply(this, [].slice.call(arguments));\n          };\n\n        }\n\n      })();");
      scriptElem.setAttribute("type", "text/javascript");
      prependElem.insertBefore(scriptElem, prependElem.firstChild);
    }

    echo("<!-- Proxified page constructed by miniProxy -->\n" + doc.saveHTML());
  } else if (stripos(contentType, "text/css") !== false) //This is CSS, so proxify url() references.
  {
    echo(proxifyCSS(responseBody, url));
  } else //This isn't a web page or CSS, so serve unmodified through the proxy with the correct headers (images, JavaScript, etc.)
  {
    header("Content-Length: " + responseBody.length, true);
    echo(responseBody);
  }
