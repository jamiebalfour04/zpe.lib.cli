import jamiebalfour.HelperFunctions;
import jamiebalfour.zpe.core.YASSByteCodes;
import jamiebalfour.zpe.core.ZPEModule;
import jamiebalfour.zpe.core.ZPEStructure;
import jamiebalfour.zpe.core.interfaces.ZPECustomFunction;
import jamiebalfour.zpe.core.interfaces.ZPELibrary;
import jamiebalfour.zpe.core.interfaces.ZPEType;
import jamiebalfour.zpe.core.types.ZPEBoolean;
import jamiebalfour.zpe.core.types.ZPEList;
import jamiebalfour.zpe.core.types.ZPEMap;
import jamiebalfour.zpe.core.types.ZPENumber;
import jamiebalfour.zpe.core.types.ZPEString;

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
  @Override
  public Map<String, ZPECustomFunction> getFunctions() {
    return new HashMap<>();
  }

  @Override
  public Map<String, Class<? extends ZPEStructure>> getObjects() {
    return new HashMap<>();
  }

  @Override
  public Map<String, ZPEModule> getModules() {
    HashMap<String, ZPEModule> map = new HashMap<>();
    map.put("CLI", new CLIModule());
    return map;
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
    return "CLI";
  }

  @Override
  public String getVersionInfo() {
    return "1.0";
  }

  public static class CLIModule extends ZPEModule {

  public CLIModule() {
    super("CLI");

    addMethod(this, "grep", new Grep());
    addMethod(this, "grep_file", new GrepFile());
    addMethod(this, "grep_count", new GrepCount());
    addMethod(this, "replace", new Replace());

    addMethod(this, "wc", new Wc());
    addMethod(this, "wc_file", new WcFile());
    addMethod(this, "head_file", new HeadFile());
    addMethod(this, "tail_file", new TailFile());

    addMethod(this, "dns_a", new DnsA());
    addMethod(this, "dns_aaaa", new DnsAAAA());
    addMethod(this, "dns_mx", new DnsMX());
    addMethod(this, "dns_txt", new DnsTXT());
    addMethod(this, "reverse_dns", new ReverseDns());
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

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
    DirContext ctx = dnsContext();
    Attributes attrs = ctx.getAttributes(host, new String[]{type});
    Attribute attr = attrs.get(type);

    ZPEList out = new ZPEList();
    if (attr == null) return out;

    NamingEnumeration<?> e = attr.getAll();
    while (e.hasMore()) {
      Object next = e.next();
      out.add(ZPEString.newStr(next == null ? "" : next.toString()));
    }
    return out;
  }

  private static String dnsQueryFirst(String host, String type) throws Exception {
    DirContext ctx = dnsContext();
    Attributes attrs = ctx.getAttributes(host, new String[]{type});
    Attribute attr = attrs.get(type);
    if (attr == null) return "";

    NamingEnumeration<?> e = attr.getAll();
    if (!e.hasMore()) return "";

    Object first = e.next();
    return first == null ? "" : first.toString();
  }

  private static String getStringArg(ZPEType[] params, int index, String defaultValue) {
    if (params == null || index >= params.length || params[index] == null) {
      return defaultValue;
    }
    return params[index].toString();
  }

  private static int getIntArg(ZPEType[] params, int index, int defaultValue) {
    if (params == null || index >= params.length || params[index] == null) {
      return defaultValue;
    }

    try {
      return HelperFunctions.stringToInteger(params[index].toString());
    } catch (Exception e) {
      return defaultValue;
    }
  }

  // =========================================================================
  // grep(text, pattern [, flags])
  // =========================================================================

  static class Grep implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Returns all lines from the provided text that match the given regex pattern.";
    }

    @Override
    public String version() {
      return "";
    }

    @Override
    public String manualHeader() {
      return "grep ([{string} text, {string} pattern [, {string} flags]])";
    }

    public int getMinimumParameters() {
      return 2;
    }

    public String[] getParameterNames() {
      return new String[]{"text", "pattern", "flags"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        String text = getStringArg(params, 0, "");
        String pattern = getStringArg(params, 1, "");
        String flags = getStringArg(params, 2, "");

        Pattern p = Pattern.compile(pattern, regexFlagsFromString(flags));
        String[] lines = splitLines(text);

        ArrayList<String> out = new ArrayList<>();
        for (String line : lines) {
          if (p.matcher(line).find()) {
            out.add(line);
          }
        }

        return toZpeList(out);
      } catch (Exception e) {
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 0;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // grep_file(path, pattern [, flags])
  // =========================================================================

  static class GrepFile implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Returns all lines from a file that match the given regex pattern.";
    }

    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "grep_file ([{string} path, {string} pattern [, {string} flags]])";
    }

    public int getMinimumParameters() {
      return 2;
    }

    public String[] getParameterNames() {
      return new String[]{"path", "pattern", "flags"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        Path path = Path.of(getStringArg(params, 0, ""));
        String pattern = getStringArg(params, 1, "");
        String flags = getStringArg(params, 2, "");

        Pattern p = Pattern.compile(pattern, regexFlagsFromString(flags));

        ArrayList<String> out = new ArrayList<>();
        for (String line : readAllLinesUtf8(path)) {
          if (p.matcher(line).find()) {
            out.add(line);
          }
        }

        return toZpeList(out);
      } catch (Exception e) {
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 3;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // grep_count(text, pattern [, flags])
  // =========================================================================

  static class GrepCount implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Counts how many lines in the provided text match the given regex pattern.";
    }

    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "grep_count ([{string} text, {string} pattern [, {string} flags]])";
    }

    public int getMinimumParameters() {
      return 2;
    }

    public String[] getParameterNames() {
      return new String[]{"text", "pattern", "flags"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        String text = getStringArg(params, 0, "");
        String pattern = getStringArg(params, 1, "");
        String flags = getStringArg(params, 2, "");

        Pattern p = Pattern.compile(pattern, regexFlagsFromString(flags));
        String[] lines = splitLines(text);

        int count = 0;
        for (String line : lines) {
          if (p.matcher(line).find()) {
            count++;
          }
        }

        return new ZPENumber(count);
      } catch (Exception e) {
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 0;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.NUMBER_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // replace(text, pattern, replacement [, flags])
  // =========================================================================

  static class Replace implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Replaces all matches of a regex pattern in text with the provided replacement string.";
    }


    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "replace ([{string} text, {string} pattern, {string} replacement [, {string} flags]])";
    }

    public int getMinimumParameters() {
      return 3;
    }

    public String[] getParameterNames() {
      return new String[]{"text", "pattern", "replacement", "flags"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        String text = getStringArg(params, 0, "");
        String pattern = getStringArg(params, 1, "");
        String replacement = getStringArg(params, 2, "");
        String flags = getStringArg(params, 3, "");

        Pattern p = Pattern.compile(pattern, regexFlagsFromString(flags));
        return ZPEString.newStr(p.matcher(text).replaceAll(replacement));
      } catch (Exception e) {
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 0;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.STRING_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // wc(text)
  // =========================================================================

  static class Wc implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Returns counts for lines, words, characters and bytes in a string.";
    }


    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "wc ([{string} text])";
    }

    public int getMinimumParameters() {
      return 1;
    }

    public String[] getParameterNames() {
      return new String[]{"text"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        String text = getStringArg(params, 0, "");
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
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 0;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.MAP_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // wc_file(path)
  // =========================================================================

  static class WcFile implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Returns counts for lines, words, characters and bytes in a UTF-8 text file.";
    }


    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "wc_file ([{string} path])";
    }

    public int getMinimumParameters() {
      return 1;
    }

    public String[] getParameterNames() {
      return new String[]{"path"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        Path p = Path.of(getStringArg(params, 0, ""));
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
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 3;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.MAP_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // head_file(path, n)
  // =========================================================================

  static class HeadFile implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Returns the first n lines of a UTF-8 text file.";
    }


    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "head_file ([{string} path, {number} n])";
    }

    public int getMinimumParameters() {
      return 2;
    }

    public String[] getParameterNames() {
      return new String[]{"path", "n"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        Path p = Path.of(getStringArg(params, 0, ""));
        int n = getIntArg(params, 1, 0);
        if (n < 0) n = 0;

        List<String> lines = readAllLinesUtf8(p);
        int end = Math.min(n, lines.size());
        return toZpeList(lines.subList(0, end));
      } catch (Exception e) {
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 3;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // tail_file(path, n)
  // =========================================================================

  static class TailFile implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Returns the last n lines of a UTF-8 text file.";
    }


    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "tail_file ([{string} path, {number} n])";
    }

    public int getMinimumParameters() {
      return 2;
    }

    public String[] getParameterNames() {
      return new String[]{"path", "n"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        Path p = Path.of(getStringArg(params, 0, ""));
        int n = getIntArg(params, 1, 0);
        if (n < 0) n = 0;

        List<String> lines = readAllLinesUtf8(p);
        int start = Math.max(0, lines.size() - n);
        return toZpeList(lines.subList(start, lines.size()));
      } catch (Exception e) {
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 3;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // dns_a(host)
  // =========================================================================

  static class DnsA implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Returns DNS A records for a host.";
    }


    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "dns_a ([{string} host])";
    }

    public int getMinimumParameters() {
      return 1;
    }

    public String[] getParameterNames() {
      return new String[]{"host"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        return dnsQueryToList(getStringArg(params, 0, ""), "A");
      } catch (Exception e) {
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 3;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // dns_aaaa(host)
  // =========================================================================

  static class DnsAAAA implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Returns DNS AAAA records for a host.";
    }


    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "dns_aaaa ([{string} host])";
    }

    public int getMinimumParameters() {
      return 1;
    }

    public String[] getParameterNames() {
      return new String[]{"host"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        return dnsQueryToList(getStringArg(params, 0, ""), "AAAA");
      } catch (Exception e) {
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 3;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // dns_mx(host)
  // =========================================================================

  static class DnsMX implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Returns DNS MX records for a host.";
    }


    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "dns_mx ([{string} host])";
    }

    public int getMinimumParameters() {
      return 1;
    }

    public String[] getParameterNames() {
      return new String[]{"host"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        return dnsQueryToList(getStringArg(params, 0, ""), "MX");
      } catch (Exception e) {
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 3;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // dns_txt(host)
  // =========================================================================

  static class DnsTXT implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Returns DNS TXT records for a host.";
    }


    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "dns_txt ([{string} host])";
    }

    public int getMinimumParameters() {
      return 1;
    }

    public String[] getParameterNames() {
      return new String[]{"host"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        return dnsQueryToList(getStringArg(params, 0, ""), "TXT");
      } catch (Exception e) {
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 3;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.LIST_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }

  // =========================================================================
  // reverse_dns(ip)
  // =========================================================================

  static class ReverseDns implements ZPEModuleMethod {

    @Override
    public String manualEntry() {
      return "Performs a reverse DNS lookup (PTR) for an IPv4 address.";
    }


    @Override
    public String version() {
      return "1.0";
    }

    @Override
    public String manualHeader() {
      return "reverse_dns ([{string} ip])";
    }

    public int getMinimumParameters() {
      return 1;
    }

    public String[] getParameterNames() {
      return new String[]{"ip"};
    }

    @Override
    public ZPEType call(ZPEType[] params) {
      try {
        String ip = getStringArg(params, 0, "");
        String[] parts = ip.split("\\.");

        if (parts.length != 4) {
          return ZPEBoolean.FALSE();
        }

        String rev = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa";
        String ptr = dnsQueryFirst(rev, "PTR");
        return ZPEString.newStr(ptr);
      } catch (Exception e) {
        return ZPEBoolean.FALSE();
      }
    }

    @Override
    public int permissionLevel() {
      return 3;
    }

    public byte[] getReturnTypes() {
      return new byte[]{YASSByteCodes.STRING_TYPE, YASSByteCodes.BOOLEAN_TYPE};
    }
  }
}}