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
import java.util.regex.Pattern;

public class Plugin implements ZPELibrary {

  private static int regexFlagsFromString(String flags) {
    if (flags == null) return 0;

    int f = 0;
    String s = flags.toLowerCase(Locale.ROOT);

    if (s.contains("i")) f |= Pattern.CASE_INSENSITIVE;
    if (s.contains("m")) f |= Pattern.MULTILINE;
    if (s.contains("s")) f |= Pattern.DOTALL;

    return f;
  }

  private static List<String> readAllLinesUtf8(Path p) throws IOException {
    return Files.readAllLines(p, StandardCharsets.UTF_8);
  }

  private static ZPEList toZpeList(List<String> lines) {
    ZPEList l = new ZPEList();
    for (String line : lines) {
      l.add(ZPEString.newStr(line));
    }
    return l;
  }

  private static String[] splitLines(String text) {
    return text.split("\\R", -1);
  }

  private static DirContext dnsContext() throws Exception {
    Hashtable<String, String> env = new Hashtable<>();
    env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
    return new InitialDirContext(env);
  }

  private static ZPEList dnsQueryToList(String host, String type) throws Exception {
    try {
      DirContext ctx = dnsContext();
      Attributes attrs = ctx.getAttributes(host, new String[]{type});
      Attribute attr = attrs.get(type);

      ZPEList out = new ZPEList();
      if (attr == null) return out;

      NamingEnumeration<?> e = attr.getAll();
      while (e.hasMore()) {
        out.add(ZPEString.newStr(e.next().toString()));
      }
      return out;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static String dnsQueryFirst(String host, String type) throws Exception {
    try {
      DirContext ctx = dnsContext();
      Attributes attrs = ctx.getAttributes(host, new String[]{type});
      Attribute attr = attrs.get(type);
      if (attr == null) return "";
      NamingEnumeration<?> e = attr.getAll();
      if (!e.hasMore()) return "";
      Object first = e.next();
      return first == null ? "" : first.toString();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // -----------------------
  // Helpers
  // -----------------------

  @Override
  public Map<String, ZPECustomFunction> getFunctions() {
    HashMap<String, ZPECustomFunction> arr = new HashMap<>();

    // Text tools
    arr.put("grep", new Grep());
    arr.put("grep_file", new GrepFile());
    arr.put("grep_count", new GrepCount());
    arr.put("replace", new Replace());

    // File/text counting
    arr.put("wc", new Wc());
    arr.put("wc_file", new WcFile());
    arr.put("head_file", new HeadFile());
    arr.put("tail_file", new TailFile());

    // DNS tools
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

  // -----------------------
  // DNS helpers (JNDI DNS provider)
  // -----------------------

  @Override
  public boolean supportsLinux() {
    return true;
  }

  @Override
  public String getName() {
    return "libCLI";
  }

  @Override
  public String getVersionInfo() {
    return "1.0";
  }

  // ============================================================
  // grep ([{string} text, {string} pattern [, {string} flags]])
  // Returns: list | boolean
  // ============================================================

  public static class Grep implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns all lines from the provided text that match the given regex pattern.";
    }

    @Override
    public String getManualHeader() {
      return "grep ([{string} text, {string} pattern [, {string} flags]])";
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
        String[] lines = splitLines(text);

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
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // grep_file ([{string} path, {string} pattern [, {string} flags]])
  // Returns: list | boolean
  // ============================================================

  public static class GrepFile implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns all lines from a file that match the given regex pattern.";
    }

    @Override
    public String getManualHeader() {
      return "grep_file ([{string} path, {string} pattern [, {string} flags]])";
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
        for (String line : readAllLinesUtf8(path)) {
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
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // grep_count ([{string} text, {string} pattern [, {string} flags]])
  // Returns: number | boolean
  // ============================================================

  public static class GrepCount implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Counts how many lines in the provided text match the given regex pattern.";
    }

    @Override
    public String getManualHeader() {
      return "grep_count ([{string} text, {string} pattern [, {string} flags]])";
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
        String[] lines = splitLines(text);

        int count = 0;
        for (String line : lines) {
          if (p.matcher(line).find()) count++;
        }

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
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.NUMBER_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // replace ([{string} text, {string} pattern, {string} replacement [, {string} flags]])
  // Returns: string | boolean
  // ============================================================

  public static class Replace implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Replaces all matches of a regex pattern in text with the provided replacement string.";
    }

    @Override
    public String getManualHeader() {
      return "replace ([{string} text, {string} pattern, {string} replacement [, {string} flags]])";
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
        String replacement = params.get("replacement").toString();
        String flags = params.containsKey("flags") ? params.get("flags").toString() : "";

        Pattern p = Pattern.compile(pattern, regexFlagsFromString(flags));
        return ZPEString.newStr(p.matcher(text).replaceAll(replacement));
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 0;
    }

    @Override
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.STRING_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // wc ([{string} text])
  // Returns: map | boolean
  // ============================================================

  public static class Wc implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns counts for lines, words, characters and bytes in a string.";
    }

    @Override
    public String getManualHeader() {
      return "wc ([{string} text])";
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

        int lines = text.isEmpty() ? 0 : splitLines(text).length;
        int words = text.trim().isEmpty() ? 0 : text.trim().split("\\s+").length;
        int chars = text.length();
        int byteCount = bytes.length;

        ZPEMap m = new ZPEMap();
        m.put(new ZPEString("lines"), new ZPENumber(lines));
        m.put(new ZPEString("words"), new ZPENumber(words));
        m.put(new ZPEString("chars"), new ZPENumber(chars));
        m.put(new ZPEString("bytes"), new ZPENumber(byteCount));
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
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.MAP_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // wc_file ([{string} path])
  // Returns: map | boolean
  // ============================================================

  public static class WcFile implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns counts for lines, words, characters and bytes in a UTF-8 text file.";
    }

    @Override
    public String getManualHeader() {
      return "wc_file ([{string} path])";
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

        int lines = text.isEmpty() ? 0 : splitLines(text).length;
        int words = text.trim().isEmpty() ? 0 : text.trim().split("\\s+").length;
        int chars = text.length();
        int byteCount = bytes.length;

        ZPEMap m = new ZPEMap();
        m.put(new ZPEString("lines"), new ZPENumber(lines));
        m.put(new ZPEString("words"), new ZPENumber(words));
        m.put(new ZPEString("chars"), new ZPENumber(chars));
        m.put(new ZPEString("bytes"), new ZPENumber(byteCount));
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
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.MAP_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // head_file ([{string} path, {number} n])
  // Returns: list | boolean
  // ============================================================

  public static class HeadFile implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns the first n lines of a UTF-8 text file.";
    }

    @Override
    public String getManualHeader() {
      return "head_file ([{string} path, {number} n])";
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

        List<String> lines = readAllLinesUtf8(p);
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
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // tail_file ([{string} path, {number} n])
  // Returns: list | boolean
  // ============================================================

  public static class TailFile implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns the last n lines of a UTF-8 text file.";
    }

    @Override
    public String getManualHeader() {
      return "tail_file ([{string} path, {number} n])";
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

        List<String> lines = readAllLinesUtf8(p);
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
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // dns_a ([{string} host])
  // Returns: list | boolean
  // ============================================================

  public static class DnsA implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns DNS A records for a host.";
    }

    @Override
    public String getManualHeader() {
      return "dns_a ([{string} host])";
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
        return dnsQueryToList(params.get("host").toString(), "A");
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // dns_aaaa ([{string} host])
  // Returns: list | boolean
  // ============================================================

  public static class DnsAAAA implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns DNS AAAA records for a host.";
    }

    @Override
    public String getManualHeader() {
      return "dns_aaaa ([{string} host])";
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
        return dnsQueryToList(params.get("host").toString(), "AAAA");
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // dns_mx ([{string} host])
  // Returns: list | boolean
  // ============================================================

  public static class DnsMX implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns DNS MX records for a host.";
    }

    @Override
    public String getManualHeader() {
      return "dns_mx ([{string} host])";
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
        return dnsQueryToList(params.get("host").toString(), "MX");
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // dns_txt ([{string} host])
  // Returns: list | boolean
  // ============================================================

  public static class DnsTXT implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Returns DNS TXT records for a host.";
    }

    @Override
    public String getManualHeader() {
      return "dns_txt ([{string} host])";
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
        return dnsQueryToList(params.get("host").toString(), "TXT");
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // ============================================================
  // reverse_dns ([{string} ip])
  // Returns: string | boolean
  // ============================================================

  public static class ReverseDns implements ZPECustomFunction {

    @Override
    public String getManualEntry() {
      return "Performs a reverse DNS lookup (PTR) for an IPv4 address.";
    }

    @Override
    public String getManualHeader() {
      return "reverse_dns ([{string} ip])";
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

        // IPv4 only for now
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
          return new ZPEBoolean(false);
        }

        String rev = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa";
        String ptr = dnsQueryFirst(rev, "PTR");
        return ZPEString.newStr(ptr);
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.STRING_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }
}