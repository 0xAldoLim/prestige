"""Headless Ghidra wrapper using a Java GhidraScript (no Python runtime required)."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from prestige.types import PolicyDenied, PrestigeError

GHIDRA_JAVA = r'''
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Data;
import ghidra.program.model.data.DataType;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

public class PrestigeExport extends GhidraScript {
    String esc(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder();
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '"') { b.append('\\'); b.append(c); }
            else if (c < 0x20) { b.append(String.format("\\u%04x", (int) c)); }
            else { b.append(c); }
        }
        b.append('"');
        return b.toString();
    }

    public void run() throws Exception {
        String path = System.getenv("PRESTIGE_EXPORT_PATH");
        String mode = System.getenv().getOrDefault("PRESTIGE_EXPORT_MODE", "functions");
        String target = System.getenv().getOrDefault("PRESTIGE_EXPORT_TARGET", "");
        StringBuilder out = new StringBuilder();
        out.append("{");
        if ("functions".equals(mode)) {
            out.append("\"functions\":[");
            boolean first = true;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (!first) out.append(",");
                first = false;
                out.append("{\"name\":").append(esc(f.getName()));
                out.append(",\"entry\":\"0x").append(f.getEntryPoint().toString()).append("\"");
                out.append(",\"length\":").append(f.getBody().getNumAddresses()).append("}");
            }
            out.append("]");
        } else if ("strings".equals(mode)) {
            out.append("\"strings\":[");
            boolean first = true;
            for (Data d : currentProgram.getListing().getData(true)) {
                DataType dt = d.getDataType();
                if (dt == null) continue;
                String name = dt.getName().toLowerCase();
                if (name.contains("string") || name.contains("unicode")) {
                    Object val = d.getValue();
                    if (val == null) continue;
                    if (!first) out.append(",");
                    first = false;
                    out.append("{\"value\":").append(esc(val.toString()));
                    out.append(",\"address\":\"0x").append(d.getAddress().toString()).append("\"}");
                }
            }
            out.append("]");
        } else if ("imports".equals(mode)) {
            out.append("\"imports\":[");
            boolean first = true;
            for (ghidra.program.model.symbol.Symbol sym : currentProgram.getSymbolTable().getExternalSymbols()) {
                if (!first) out.append(",");
                first = false;
                out.append("{\"name\":").append(esc(sym.getName()));
                out.append(",\"address\":\"0x").append(sym.getAddress().toString()).append("\"}");
            }
            out.append("]");
        } else if ("exports".equals(mode)) {
            out.append("\"exports\":[");
            boolean first = true;
            for (ghidra.program.model.symbol.Symbol sym : currentProgram.getSymbolTable().getSymbols(currentProgram.getMinAddress())) {
                if (sym.getSymbolType().toString().equals("Function")) {
                    if (!first) out.append(",");
                    first = false;
                    out.append("{\"name\":").append(esc(sym.getName()));
                    out.append(",\"address\":\"0x").append(sym.getAddress().toString()).append("\"}");
                }
            }
            out.append("]");
        } else if ("decompile".equals(mode)) {
            DecompInterface iface = new DecompInterface();
            iface.openProgram(currentProgram);
            ghidra.program.model.address.Address addr = currentProgram.getAddressFactory().getAddress(target);
            Function f = currentProgram.getFunctionManager().getFunctionContaining(addr);
            if (f != null) {
                DecompileResults res = iface.decompileFunction(f, 30, null);
                out.append("\"function\":").append(esc(f.getName()));
                out.append(",\"entry\":\"0x").append(f.getEntryPoint().toString()).append("\"");
                out.append(",\"c\":").append(esc(res.getDecompiledFunction().getC()));
            } else {
                out.append("\"error\":\"no function at target address\"");
            }
        } else {
            out.append("\"error\":\"unknown mode\"");
        }
        out.append("}");
        java.nio.file.Files.write(java.nio.file.Paths.get(path), out.toString().getBytes("UTF-8"));
    }
}
'''

_ALLOWED_MODES = {"functions", "strings", "imports", "exports", "decompile"}


class GhidraAdapter:
    def __init__(self, ghidra_home: str | None = None):
        home = Path(ghidra_home or "/usr/share/ghidra")
        self.headless = home / "support" / "analyzeHeadless"
        if not self.headless.exists():
            raise PolicyDenied("Ghidra headless analyzer not found")

    def analyze(
        self,
        binary: Path,
        mode: str = "functions",
        target: str = "",
        timeout: int = 180,
    ) -> dict:
        if mode not in _ALLOWED_MODES:
            raise PolicyDenied(f"Unsupported Ghidra analysis mode: {mode}")
        if mode == "decompile" and not target:
            raise PolicyDenied("decompile mode requires a target address")
        if not isinstance(target, str) or not all(
            c in "0123456789abcdefxABCDEFX_" for c in target
        ):
            raise PolicyDenied("Invalid Ghidra target address")
        binary = Path(binary).resolve()
        if not binary.is_file():
            raise PrestigeError("Analysis target is not a file")

        with tempfile.TemporaryDirectory(prefix="prestige-ghidra-") as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "project"
            workspace.mkdir(parents=True, exist_ok=True)
            script_dir = tmp_path / "scripts"
            script_dir.mkdir()
            script_file = script_dir / "PrestigeExport.java"
            script_file.write_text(GHIDRA_JAVA, encoding="utf-8")
            output = tmp_path / "export.json"

            env = os.environ.copy()
            env["PRESTIGE_EXPORT_PATH"] = str(output)
            env["PRESTIGE_EXPORT_MODE"] = mode
            env["PRESTIGE_EXPORT_TARGET"] = target

            cmd = [
                str(self.headless),
                str(workspace),
                "prestige",
                "-import",
                str(binary),
                "-scriptPath",
                str(script_dir),
                "-postScript",
                "PrestigeExport.java",
                "-deleteProject",
            ]
            try:
                completed = subprocess.run(
                    cmd,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=max(10, min(600, timeout)),
                    check=False,
                )
            except FileNotFoundError as error:
                raise PolicyDenied("Ghidra analyzer could not be executed") from error
            except subprocess.TimeoutExpired as error:
                raise PrestigeError("Ghidra analysis exceeded deadline") from error
            if not output.exists():
                tail = completed.stdout[-4096:] + completed.stderr[-2048:]
                raise PrestigeError("Ghidra produced no output; log tail:\n" + tail)
            data = json.loads(output.read_text(encoding="utf-8"))
            data["_ghidra_returncode"] = completed.returncode
            return data
