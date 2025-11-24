var metadata = {
    name: "PostEx-BOF",
    description: "BOFs for post exploitation"
};

/// COMMANDS

var cmd_underlaycopy = ax.create_command("underlaycopy", "Copy file using low-level NTFS access (MFT or Metadata mode)", "underlaycopy MFT C:\\Windows\\System32\\notepad.exe C:\\temp\\notepad_copy.exe");
cmd_underlaycopy.addArgString("mode", true, "Copy mode: MFT or Metadata");
cmd_underlaycopy.addArgString("source", true, "Source file path");
cmd_underlaycopy.addArgString("destination", true, "Destination file path");
cmd_underlaycopy.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let mode = parsed_json["mode"];
    let source = parsed_json["source"];
    let dest = parsed_json["destination"];

    if (mode !== "MFT" && mode !== "Metadata") {
        ax.console_message(id, "Error: Mode must be 'MFT' or 'Metadata'", "error");
        return;
    }

    let bof_params = ax.bof_pack("cstr,cstr,cstr", [mode, source, dest]);
    // Map architecture: x32 -> x86, x64 -> x64
    let arch = ax.arch(id);
    let arch_suffix = (arch === "x32") ? "x86" : arch;
    let bof_path = ax.script_dir() + "_bin/underlaycopy." + arch_suffix + ".o";

    let cmd = "execute bof";
    if (ax.agent_info(id, "type") == "kharon") { cmd = "exec-bof"; }

    ax.execute_alias(id, cmdline, `${cmd} ${bof_path} ${bof_params}`, "Task: UnderlayCopy file copy");
});

var group_underlaycopy = ax.create_commands_group("UnderlayCopy-BOF", [cmd_underlaycopy]);
ax.register_commands_group(group_underlaycopy, ["beacon", "gopher"], ["windows"], []);

