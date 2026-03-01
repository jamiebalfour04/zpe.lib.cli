import jamiebalfour.HelperFunctions;
import jamiebalfour.zpe.core.YASSByteCodes;
import jamiebalfour.zpe.core.ZPEFunction;
import jamiebalfour.zpe.core.ZPERuntimeEnvironment;
import jamiebalfour.zpe.core.ZPEStructure;
import jamiebalfour.zpe.interfaces.ZPECustomFunction;
import jamiebalfour.zpe.interfaces.ZPELibrary;
import jamiebalfour.zpe.interfaces.ZPEType;
import jamiebalfour.zpe.types.*;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Plugin implements ZPELibrary {

  // -----------------------
  // Helpers
  // -----------------------
  private static int regexFlagsFromString(String flags) {
    if (flags == null) return 0;
    int f = 0;
    String s = flags.toLowerCase(Locale.ROOT);
    if (s.contains("i")) f |= Pattern.CASE_INSENSITIVE;
    if (s.contains("m")) f |= Pattern.MULTILINE;
    if (s.contains("s")) f |= Pattern.DOTALL;
    return f;
  }

  private static List<String> readAllLines(Path p) throws IOException {
    return Files.readAllLines(p, StandardCharsets.UTF_8);
  }

  private static ZPEList toZpeList(List<String> lines) {
    ZPEList l = new ZPEList();
    for (String line : lines) l.add(new ZPEString(line));
    return l;
  }

  private static ZPEString zStr(String s) {
    return ZPEString.newStr(s);
  }

  // -----------------------
  // DNS helpers
  // -----------------------
  private static DirContext dnsContext() throws Exception {
    Hashtable<String, String> env = new Hashtable<>();
    env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
    return new InitialDirContext(env);
  }

  private static ZPEList dnsQuery(String host, String type) throws Exception {
    try {
      DirContext ctx = dnsContext();
      Attributes attrs = ctx.getAttributes(host, new String[]{type});
      Attribute attr = attrs.get(type);
      ZPEList out = new ZPEList();
      if (attr == null) return out;
      NamingEnumeration<?> e = attr.getAll();
      while (e.hasMore()) out.add(zStr(e.next().toString()));
      return out;
    } finally {
      dnsContext().close();
    }
  }

  @Override
  public Map<String, ZPECustomFunction> getFunctions() {
    HashMap<String, ZPECustomFunction> arr = new HashMap<>();

    // grep / replace / wc
    arr.put("grep", new Grep());
    arr.put("grep_file", new GrepFile());
    arr.put("grep_count", new GrepCount());
    arr.put("replace", new Replace());

    arr.put("wc", new Wc());
    arr.put("wc_file", new WcFile());

    arr.put("head_file", new HeadFile());
    arr.put("tail_file", new TailFile());

    // DNS
    arr.put("dns_a", new DnsA());
    arr.put("dns_aaaa", new DnsAAAA());
    arr.put("dns_mx", new DnsMX());
    arr.put("dns_txt", new DnsTXT());
    arr.put("reverse_dns", new ReverseDns());

    return arr;
  }

  @Override
  public Map<String, Class<? extends ZPEStructure>> getObjects() {
    return null;
  }

  @Override
  public boolean supportsWindows() {
    return true;
  }

  @Override
  public boolean supportsMacOs() {
    return true;
  }

  @Override
  public boolean supportsLinux() {
    return true;
  }

  @Override
  public String getName() {
    return "libTools";
  }

  @Override
  public String getVersionInfo() {
    return "1.0";
  }

  // -----------------------
  // grep(text, pattern[, flags]) => list
  // -----------------------
  public static class Grep implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns matching lines from text using a regex pattern.";
    }

    @Override
    public String getManualHeader() {
      return "grep";
    }

    @Override
    public int getMinimumParameters() {
      return 2;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"text", "pattern", "flags"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        String text = params.get("text").toString();
        String pattern = params.get("pattern").toString();
        String flags = params.containsKey("flags") ? params.get("flags").toString() : "";

        Pattern p = Pattern.compile(pattern, regexFlagsFromString(flags));
        String[] lines = text.split("\\R", -1);

        ArrayList<String> out = new ArrayList<>();
        for (String line : lines) {
          if (p.matcher(line).find()) out.add(line);
        }
        return toZpeList(out);
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 0;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }

  // grep_file(path, pattern[, flags]) => list
  public static class GrepFile implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns matching lines from a file using a regex pattern.";
    }

    @Override
    public String getManualHeader() {
      return "grep_file";
    }

    @Override
    public int getMinimumParameters() {
      return 2;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"path", "pattern", "flags"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        Path path = Path.of(params.get("path").toString());
        String pattern = params.get("pattern").toString();
        String flags = params.containsKey("flags") ? params.get("flags").toString() : "";

        Pattern p = Pattern.compile(pattern, regexFlagsFromString(flags));

        ArrayList<String> out = new ArrayList<>();
        for (String line : readAllLines(path)) {
          if (p.matcher(line).find()) out.add(line);
        }
        return toZpeList(out);
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }

  // grep_count(text, pattern[, flags]) => number
  public static class GrepCount implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Counts matching lines from text using a regex pattern.";
    }

    @Override
    public String getManualHeader() {
      return "grep_count";
    }

    @Override
    public int getMinimumParameters() {
      return 2;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"text", "pattern", "flags"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        String text = params.get("text").toString();
        String pattern = params.get("pattern").toString();
        String flags = params.containsKey("flags") ? params.get("flags").toString() : "";

        Pattern p = Pattern.compile(pattern, regexFlagsFromString(flags));
        String[] lines = text.split("\\R", -1);

        int count = 0;
        for (String line : lines) {
          if (p.matcher(line).find()) count++;
        }

        // If your numeric type is different, swap this constructor.
        return new ZPENumber(count);

      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 0;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }

  // replace(text, pattern, replacement[, flags]) => string
  public static class Replace implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Replaces all matches in text using a regex pattern.";
    }

    @Override
    public String getManualHeader() {
      return "replace";
    }

    @Override
    public int getMinimumParameters() {
      return 3;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"text", "pattern", "replacement", "flags"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        String text = params.get("text").toString();
        String pattern = params.get("pattern").toString();
        String repl = params.get("replacement").toString();
        String flags = params.containsKey("flags") ? params.get("flags").toString() : "";

        Pattern p = Pattern.compile(pattern, regexFlagsFromString(flags));
        Matcher m = p.matcher(text);
        return zStr(m.replaceAll(repl));
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 0;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.STRING_TYPE;
    }
  }

  // wc(text) => map {lines, words, chars, bytes}
  public static class Wc implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns counts for lines, words, chars and bytes for a string.";
    }

    @Override
    public String getManualHeader() {
      return "wc";
    }

    @Override
    public int getMinimumParameters() {
      return 1;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"text"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        String text = params.get("text").toString();
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);

        int lines = text.isEmpty() ? 0 : text.split("\\R", -1).length;
        int words = text.trim().isEmpty() ? 0 : text.trim().split("\\s+").length;
        int chars = text.length();
        int b = bytes.length;

        ZPEMap m = new ZPEMap();
        m.put(new ZPEString("lines"), new ZPENumber(lines));
        m.put(new ZPEString("words"), new ZPENumber(words));
        m.put(new ZPEString("chars"), new ZPENumber(chars));
        m.put(new ZPEString("bytes"), new ZPENumber(b));
        return m;

      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 0;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }

  // wc_file(path) => map
  public static class WcFile implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns counts for lines, words, chars and bytes for a file.";
    }

    @Override
    public String getManualHeader() {
      return "wc_file";
    }

    @Override
    public int getMinimumParameters() {
      return 1;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"path"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        Path p = Path.of(params.get("path").toString());
        byte[] bytes = Files.readAllBytes(p);
        String text = new String(bytes, StandardCharsets.UTF_8);

        int lines = text.isEmpty() ? 0 : text.split("\\R", -1).length;
        int words = text.trim().isEmpty() ? 0 : text.trim().split("\\s+").length;
        int chars = text.length();
        int b = bytes.length;

        ZPEMap m = new ZPEMap();
        m.put(new ZPEString("lines"), new ZPENumber(lines));
        m.put(new ZPEString("words"), new ZPENumber(words));
        m.put(new ZPEString("chars"), new ZPENumber(chars));
        m.put(new ZPEString("bytes"), new ZPENumber(b));
        return m;

      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }

  // head_file(path, n) => list
  public static class HeadFile implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns the first n lines of a file.";
    }

    @Override
    public String getManualHeader() {
      return "head_file";
    }

    @Override
    public int getMinimumParameters() {
      return 2;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"path", "n"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        Path p = Path.of(params.get("path").toString());
        int n = HelperFunctions.stringToInteger(params.get("n").toString());
        if (n < 0) n = 0;

        List<String> lines = readAllLines(p);
        int end = Math.min(n, lines.size());
        return toZpeList(lines.subList(0, end));
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }

  // tail_file(path, n) => list
  public static class TailFile implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns the last n lines of a file.";
    }

    @Override
    public String getManualHeader() {
      return "tail_file";
    }

    @Override
    public int getMinimumParameters() {
      return 2;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"path", "n"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        Path p = Path.of(params.get("path").toString());
        int n = HelperFunctions.stringToInteger(params.get("n").toString());
        if (n < 0) n = 0;

        List<String> lines = readAllLines(p);
        int start = Math.max(0, lines.size() - n);
        return toZpeList(lines.subList(start, lines.size()));
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }

  public static class DnsA implements ZPECustomFunction {
    @Override
    public String getManualEntry() {
      return "Returns A records for a host.";
    }

    @Override
    public String getManualHeader() {
      return "dns_a";
    }

    @Override
    public int getMinimumParameters() {
      return 1;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"host"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        return dnsQuery(params.get("host").toString(), "A");
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }

  public static class DnsAAAA implements ZPECustomFunction {
    @Override
    public String getManualEntry() {
      return "Returns AAAA records for a host.";
    }

    @Override
    public String getManualHeader() {
      return "dns_aaaa";
    }

    @Override
    public int getMinimumParameters() {
      return 1;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"host"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        return dnsQuery(params.get("host").toString(), "AAAA");
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }

  public static class DnsMX implements ZPECustomFunction {
    @Override
    public String getManualEntry() {
      return "Returns MX records for a host.";
    }

    @Override
    public String getManualHeader() {
      return "dns_mx";
    }

    @Override
    public int getMinimumParameters() {
      return 1;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"host"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        return dnsQuery(params.get("host").toString(), "MX");
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }

  public static class DnsTXT implements ZPECustomFunction {
    @Override
    public String getManualEntry() {
      return "Returns TXT records for a host.";
    }

    @Override
    public String getManualHeader() {
      return "dns_txt";
    }

    @Override
    public int getMinimumParameters() {
      return 1;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"host"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        return dnsQuery(params.get("host").toString(), "TXT");
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }

  public static class ReverseDns implements ZPECustomFunction {
    @Override
    public String getManualEntry() {
      return "Performs a reverse DNS lookup for an IP address.";
    }

    @Override
    public String getManualHeader() {
      return "reverse_dns";
    }

    @Override
    public int getMinimumParameters() {
      return 1;
    }

    @Override
    public String[] getParameterNames() {
      return new String[]{"ip"};
    }

    @Override
    public ZPEType MainMethod(HashMap<String, Object> params, ZPERuntimeEnvironment runtime, ZPEFunction fn) {
      try {
        String ip = params.get("ip").toString();
        // For reverse DNS via JNDI DNS provider, query PTR on in-addr.arpa / ip6.arpa.
        // Keep it simple for IPv4 first:
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return new ZPEBoolean(false);
        String rev = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa";
        ZPEList ptr = dnsQuery(rev, "PTR");
        if (ptr.isEmpty()) return zStr("");
        return ptr.get(0);
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte getReturnType() {
      return YASSByteCodes.MIXED_TYPE;
    }
  }
}