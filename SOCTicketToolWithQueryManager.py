
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import re
import pyperclip
import csv
import json
from datetime import datetime, timedelta

# Appearance/Coloring
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# UI constants
BUTTON_BORDER_COLOR = "#10674a"
BUTTON_TEXT_COLOR = "#106848"
BUTTON_HOVER_COLOR = "#8bc756"
BUTTON_FONT = ("Krub", 14)  # If Krub isn't installed, system will fallback
SEPARATOR = "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
QUERIES_FILE = "defender_queries.json"

# Globals
csv_file_path = None
saved_queries = []

#Parsing + CSV enrichment

def parse_email(text):
    data = {
        "description": "",
        "analysis": "",
        "source_ip": "",
        "source_port": "",
        "dest_ip": "",
        "dest_port": ""
    }

    # Extract main sections
    desc_match = re.search(r"Description\s*(.*?)(?=\n\s*Analysis|$)", text, re.DOTALL | re.IGNORECASE)
    if desc_match:
        data["description"] = desc_match.group(1).strip()

    analysis_match = re.search(r"Analysis\s*(.*?)(?=\n\s*Recommendations|$)", text, re.DOTALL | re.IGNORECASE)
    if analysis_match:
        data["analysis"] = analysis_match.group(1).strip()

        # Flexible IP + port detection (Cause sometimes the wording isn't exact or its omitted)
        src_ip_match = re.search(r"[Ss]ource\s+IP\s*(?:is|was|:)?\s*([0-9]+(?:\.[0-9]+){3})", data["analysis"])
        dst_ip_match = re.search(r"[Dd]estination\s+IP\s*(?:is|was|:)?\s*([0-9]+(?:\.[0-9]+){3})", data["analysis"])
        port_match = re.search(r"\bport\s+(\d{1,5})\b", data["analysis"])

        data["source_ip"] = src_ip_match.group(1) if src_ip_match else ""
        data["dest_ip"] = dst_ip_match.group(1) if dst_ip_match else ""
        data["dest_port"] = port_match.group(1) if port_match else ""

    return data

def enrich_with_csv(parsed, csv_path):
    timestamp_str = ""
    payload_input = ""
    enriched_src_port = parsed.get("source_port") or ""
    enriched_dst_port = parsed.get("dest_port") or ""

    try:
        with open(csv_path, newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            if "event_json" not in (reader.fieldnames or []):
                return "event_json not found", "", enriched_src_port, enriched_dst_port

            best_match_score = 0
            best_timestamp = ""
            best_payload = ""
            best_src_port = enriched_src_port
            best_dst_port = enriched_dst_port

            for row in reader:
                raw_event = (row.get("event_json") or "").strip()
                json_start = raw_event.find("{")
                if json_start == -1:
                    continue
                try:
                    event = json.loads(raw_event[json_start:])
                except Exception:
                    continue

                src_ip = str(event.get("src_ip") or event.get("flow", {}).get("src_ip", ""))
                src_port = str(event.get("src_port") or event.get("flow", {}).get("src_port", ""))
                dest_ip = str(event.get("dest_ip") or event.get("flow", {}).get("dest_ip", ""))
                dest_port = str(event.get("dest_port") or event.get("flow", {}).get("dest_port", ""))

                # Match scoring - Uses this for most recent timestamp, typically top of CSV
                match_score = sum([
                    bool(parsed["source_ip"]) and parsed["source_ip"] == src_ip,
                    bool(parsed["source_port"]) and parsed["source_port"] == src_port,
                    bool(parsed["dest_ip"]) and parsed["dest_ip"] == dest_ip,
                    bool(parsed["dest_port"]) and parsed["dest_port"] == dest_port
                ])

                if match_score > best_match_score:
                    best_match_score = match_score
                    timestamp_raw = event.get("timestamp") or event.get("flow", {}).get("start", "")
                    if timestamp_raw:
                        try:
                            dt = datetime.fromisoformat(timestamp_raw.replace(" 0000", ""))
                            best_timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            best_timestamp = timestamp_raw
                    best_payload = event.get("payload", "") or ""
                    best_src_port = src_port
                    best_dst_port = dest_port

            if best_match_score == 0:
                timestamp_str = "no specific event found"
            else:
                timestamp_str = best_timestamp
                payload_input = best_payload
                enriched_src_port = best_src_port or enriched_src_port
                enriched_dst_port = best_dst_port or enriched_dst_port

    except Exception as e:
        timestamp_str = f"Error: {e}"

    return timestamp_str, payload_input, enriched_src_port, enriched_dst_port



# For queries to persist throughout the session
def load_saved_queries():
    global saved_queries
    try:
        with open(QUERIES_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            if isinstance(loaded, list):
                saved_queries = loaded
    except Exception:
        saved_queries = []

def save_queries_to_file():
    try:
        with open(QUERIES_FILE, "w", encoding="utf-8") as f:
            json.dump(saved_queries, f, indent=2)
        query_status_label.configure(text="Saved ✅")
        root.after(1500, lambda: query_status_label.configure(text=""))
    except Exception:
        query_status_label.configure(text="Save failed", text_color="red")
        root.after(1500, lambda: query_status_label.configure(text=""))

# Ticket area
def generate_ticket():
    parsed = parse_email(email_box.get("1.0", "end"))

    # Enable Enrich button only if CSV is loaded and at least one IP or port is present
    if (
        csv_file_path
        and any([parsed["source_ip"], parsed["source_port"], parsed["dest_ip"], parsed["dest_port"]])
    ):
        enrich_btn.configure(state="normal")
    else:
        enrich_btn.configure(state="disabled")

    out = (
        f"**Description:**\n\n{parsed['description']}{SEPARATOR}"
        f"**Analysis:**\n\n{parsed['analysis']}{SEPARATOR}"
        f"**Recommendations:**\n\n\n{SEPARATOR}"
        f"**Supporting Details:**\n\nTimestamp:\n\n"
        f"Source IP: {parsed['source_ip']}\nPort: {parsed['source_port']}\nFrom: https://www.whois.com/whois/\n\n"
        f"Destination IP: {parsed['dest_ip']}\nPort: {parsed['dest_port']}\nFrom: https://www.whois.com/whois/\n"
        f"{SEPARATOR}"
        f"**Splunk:**\n\nTimeframe:\n\nInternal IP:\n\nMAC:\n\nNetID:\n{SEPARATOR}"
        f"**OSINT:**\n\n{SEPARATOR}"
        f"**Streamdata:**\n\nFrom: https://gchq.github.io/CyberChef\n\nInput:\n\nOutput:\n"
    )

    # Update output box
    output_box.configure(state="normal")
    output_box.delete("1.0", "end")
    output_box.insert("end", out)


def copy_ticket():
    pyperclip.copy(output_box.get("1.0", "end"))
    ticket_copy_label.configure(text="Copied ✅")
    root.after(1500, lambda: ticket_copy_label.configure(text=""))

def clear_input():
    email_box.delete("1.0", "end")
    enrich_btn.configure(state="disabled")

def select_csv():
    global csv_file_path
    csv_file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if csv_file_path:
        csv_label.configure(text="CSV Loaded ✅")
        # Enablse the Enrich button since a valid CSV is now loaded
        enrich_btn.configure(state="normal")
    else:
        csv_label.configure(text="")
        enrich_btn.configure(state="disabled")

def enrich_ticket():
    if not csv_file_path:
        return

    parsed = parse_email(email_box.get("1.0", "end"))
    ts, payload, src_port, dst_port = enrich_with_csv(parsed, csv_file_path)

    content = output_box.get("1.0", "end")

    # Replace timestamp and payload
    content = re.sub(r"(Timestamp:).*?(Source IP:)", f"\\1 {ts}\n\n\\2", content, flags=re.DOTALL)
    content = re.sub(r"(Input:\n).*?(Output:)", f"\\1{payload}\n\\2", content, flags=re.DOTALL)

    # Replace missing ports if empty
    content = re.sub(r"(Source IP:.*?\nPort:)\s*\n", f"\\1 {src_port}\n", content)
    content = re.sub(r"(Destination IP:.*?\nPort:)\s*\n", f"\\1 {dst_port}\n", content)

    output_box.configure(state="normal")
    output_box.delete("1.0", "end")
    output_box.insert("end", content)
    output_box.configure(state="normal")

    ticket_status_label.configure(text="Enriched ✅")
    root.after(1500, lambda: ticket_status_label.configure(text=""))

# Query Manager

def refresh_query_listbox():
    query_listbox.delete(0, "end")
    for idx, q in enumerate(saved_queries, start=1):
        first_line = q.splitlines()[0] if q.strip() else ""
        preview = first_line[:80] + ("..." if len(first_line) > 80 else "")
        query_listbox.insert("end", f"{idx}. {preview}")

def add_query():
    q = query_editor.get("1.0", "end").strip()
    if not q:
        return
    saved_queries.append(q)
    refresh_query_listbox()
    query_editor.delete("1.0", "end")
    save_queries_to_file()

def load_selected_query():
    sel = query_listbox.curselection()
    if not sel:
        return
    idx = sel[0]
    query_editor.delete("1.0", "end")
    query_editor.insert("end", saved_queries[idx])

def save_selected_query():
    sel = query_listbox.curselection()
    if not sel:
        return
    idx = sel[0]
    saved_queries[idx] = query_editor.get("1.0", "end").strip()
    refresh_query_listbox()
    save_queries_to_file()

def copy_selected_query():
    sel = query_listbox.curselection()
    if not sel:
        return
    idx = sel[0]
    pyperclip.copy(saved_queries[idx])
    query_copy_label.configure(text="Copied ✅")
    root.after(1500, lambda: query_copy_label.configure(text=""))

def clear_all():
    """
    Clears everything: email input, generated ticket, loaded CSV, UI indicators, and disables enrich button.
    """
    global csv_file_path
    csv_file_path = ""  # clear the loaded CSV path

    # Clear email input
    try:
        email_box.delete("1.0", "end")
    except Exception:
        try:
            email_box.delete("0.0", "end")
        except Exception:
            pass

    # Clear generated ticket output
    try:
        output_box.configure(state="normal")
        output_box.delete("1.0", "end")
        output_box.configure(state="normal")
    except Exception:
        pass

    # Reset buttons
    try:
        enrich_btn.configure(state="disabled")
    except Exception:
        pass

    # Clear labels
    try:
        csv_label.configure(text="")
    except Exception:
        pass
    try:
        ticket_status_label.configure(text="")
    except Exception:
        pass
    try:
        query_status_label.configure(text="")
    except Exception:
        pass
    try:
        query_copy_label.configure(text="")
    except Exception:
        pass



def append_timestamp_to_selected():
    """
    Append a TimeGenerated between(...) clause to the selected saved query.
    - Validates timestamp format YYYY-MM-DD HH:MM:SS.
    - Uses minutes from minutes_before_input entry (applies +/- same value).
    - Writes the appended query into the editor and saves the change back to saved_queries,
      refreshes the list preview, and persists to disk with save_queries_to_file().
    - Shows inline status messages via query_status_label.
    """
    # Check selection
    sel = query_listbox.curselection()
    if not sel:
        try:
            query_status_label.configure(text="Select a query first", text_color="red")
            root.after(1800, lambda: query_status_label.configure(text=""))
        except Exception:
            pass
        return

    idx = sel[0]

    # Get and validate timestamp
    ts_text = timestamp_input.get().strip()
    if not ts_text:
        query_status_label.configure(text="Timestamp required", text_color="red")
        root.after(1800, lambda: query_status_label.configure(text=""))
        return

    try:
        base_dt = datetime.strptime(ts_text, "%Y-%m-%d %H:%M:%S")
    except Exception:
        query_status_label.configure(text="Timestamp format: YYYY-MM-DD HH:MM:SS", text_color="red")
        root.after(2200, lambda: query_status_label.configure(text=""))
        return

    # Validate minutes (single integer used as +/-,fastest for Defender queries)
    mins_text = minutes_before_input.get().strip()
    if not mins_text.isdigit():
        query_status_label.configure(text="Minutes must be an integer", text_color="red")
        root.after(1800, lambda: query_status_label.configure(text=""))
        return
    mins = int(mins_text)

    # Compose start/end datetimes (KQL-ready, keep same formatting as earlier)
    start_dt = (base_dt - timedelta(minutes=mins)).isoformat(sep=" ", timespec="seconds")
    end_dt = (base_dt + timedelta(minutes=mins)).isoformat(sep=" ", timespec="seconds")

    # Build appended clause
    appended_clause = f"\n| where TimeGenerated between (datetime({start_dt}) .. datetime({end_dt}))"

    # Update the selected saved query and persist
    try:
        original = saved_queries[idx]
        # If the saved query already contains a "where TimeGenerated between", remove it so we don't append duplicates.
        cleaned = re.sub(r"\| where TimeGenerated between .*", "", original, flags=re.IGNORECASE | re.DOTALL).rstrip()
        new_query = cleaned + appended_clause

        # Put result into editor (so user can review/edit), and save back to list & disk
        query_editor.delete("1.0", "end")
        query_editor.insert("end", new_query)

        # Overwrite saved query with appended version and persist
        saved_queries[idx] = new_query
        refresh_query_listbox()       # refresh preview list
        save_queries_to_file()        # persist
        query_status_label.configure(text="Timestamp appended and saved ✅", text_color="green")
        root.after(2200, lambda: query_status_label.configure(text=""))
    except Exception as e:
        query_status_label.configure(text="Failed to append timestamp", text_color="red")
        root.after(1800, lambda: query_status_label.configure(text=""))
        # optional: print(e) for debugging in console -- literally saving grace


# Building the UI -- this shit is so buns
root = ctk.CTk()
root.title("SOC Ticket Tool")
root.geometry("1300x900")

# layout weights so top gets most space and is resizable
root.grid_rowconfigure(0, weight=4)   # ticket area (bigger)
root.grid_rowconfigure(1, weight=2)   # query area (smaller)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

# --- Top left (email) ---
left_frame = ctk.CTkFrame(root)
left_frame.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
left_frame.grid_rowconfigure(1, weight=1)
left_frame.grid_columnconfigure(0, weight=1)

# Label for Email Box
ctk.CTkLabel(left_frame, text="Paste MS-ISAC Email:", font=BUTTON_FONT).grid(row=0, column=0, sticky="w", pady=(0,6))

# Textbox for email input
email_box = ctk.CTkTextbox(left_frame, height=300)
email_box.grid(row=1, column=0, sticky="nsew")

# Frame for buttons
left_btn_frame = ctk.CTkFrame(left_frame)
left_btn_frame.grid(row=2, column=0, pady=6, sticky="ew")
left_btn_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)  # Column 4 for the enrich button

# Create the buttons
ctk.CTkButton(left_btn_frame, text="Generate Ticket", command=generate_ticket,
              fg_color="transparent", border_color=BUTTON_BORDER_COLOR, border_width=2,
              text_color=BUTTON_TEXT_COLOR, hover_color=BUTTON_HOVER_COLOR).grid(row=0, column=0, padx=4)

ctk.CTkButton(left_btn_frame, text="Copy Ticket", command=copy_ticket,
              fg_color="transparent", border_color=BUTTON_BORDER_COLOR, border_width=2,
              text_color=BUTTON_TEXT_COLOR, hover_color=BUTTON_HOVER_COLOR).grid(row=0, column=1, padx=4)

ctk.CTkButton(left_btn_frame, text="Select CSV", command=select_csv,
              fg_color="transparent", border_color=BUTTON_BORDER_COLOR, border_width=2,
              text_color=BUTTON_TEXT_COLOR, hover_color=BUTTON_HOVER_COLOR).grid(row=0, column=2, padx=4)

ctk.CTkButton(left_btn_frame, text="Clear All", command=clear_input,
              fg_color="transparent", border_color=BUTTON_BORDER_COLOR, border_width=2,
              text_color=BUTTON_TEXT_COLOR, hover_color=BUTTON_HOVER_COLOR, font=BUTTON_FONT).grid(row=0, column=3, padx=4)

# Enrich CSV button initially disabled
enrich_btn = ctk.CTkButton(left_btn_frame, text="Enrich CSV", command=enrich_ticket, state="disabled",
                           fg_color="transparent", border_color=BUTTON_BORDER_COLOR, border_width=2,
                           text_color=BUTTON_TEXT_COLOR, hover_color=BUTTON_HOVER_COLOR)
enrich_btn.grid(row=0, column=4, padx=4)

# Labels for ticket status and CSV info
ticket_status_label = ctk.CTkLabel(left_frame, text="", font=("Krub", 12))
ticket_status_label.grid(row=3, column=0, sticky="w", pady=(4,0))

csv_label = ctk.CTkLabel(left_frame, text="", font=("Krub", 12))
csv_label.grid(row=3, column=1, sticky="e", pady=(4,0))  # Place this label in column 1 instead of column 0


# --- Top right (output) ---
right_frame = ctk.CTkFrame(root)
right_frame.grid(row=0, column=1, padx=8, pady=8, sticky="nsew")
right_frame.grid_rowconfigure(1, weight=1)
right_frame.grid_columnconfigure(0, weight=1)

ctk.CTkLabel(right_frame, text="Generated Ticket:", font=BUTTON_FONT).grid(row=0, column=0, sticky="w", pady=(0,6))
output_box = ctk.CTkTextbox(right_frame)
output_box.grid(row=1, column=0, sticky="nsew")
ticket_copy_label = ctk.CTkLabel(right_frame, text="", font=("Krub", 12))
ticket_copy_label.grid(row=2, column=0, sticky="w", pady=(6,0))

# --- Bottom: query manager (smaller) ---
bottom_frame = ctk.CTkFrame(root)
bottom_frame.grid(row=1, column=0, columnspan=2, padx=8, pady=(0,8), sticky="nsew")
bottom_frame.grid_columnconfigure(0, weight=1)
bottom_frame.grid_columnconfigure(1, weight=2)

ctk.CTkLabel(bottom_frame, text="Saved Defender Queries (select index):", font=BUTTON_FONT).grid(row=0, column=0, sticky="w")

# listbox + scrollbar (tk.Listbox)
list_frame = tk.Frame(bottom_frame)
list_frame.grid(row=1, column=0, sticky="nsew", padx=(0,6))
list_frame.rowconfigure(0, weight=1)
list_frame.columnconfigure(0, weight=1)
query_listbox = tk.Listbox(list_frame, width=50, height=10)
query_listbox.grid(row=0, column=0, sticky="nsew")
scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=query_listbox.yview)
scrollbar.grid(row=0, column=1, sticky="ns")
query_listbox.configure(yscrollcommand=scrollbar.set)

# right: editor & controls
ctk.CTkLabel(bottom_frame, text="Query Editor / Append Timestamp:", font=BUTTON_FONT).grid(row=0, column=1, sticky="w")
query_editor = ctk.CTkTextbox(bottom_frame, height=120)
query_editor.grid(row=1, column=1, sticky="nsew", pady=(0,6))

# editor buttons
editor_frame = ctk.CTkFrame(bottom_frame)
editor_frame.grid(row=2, column=1, sticky="ew")
editor_frame.grid_columnconfigure((0,1,2,3), weight=1)

ctk.CTkButton(editor_frame, text="Add Query", command=add_query).grid(row=0, column=0, padx=4)
ctk.CTkButton(editor_frame, text="Load Selected", command=load_selected_query).grid(row=0, column=1, padx=4)
ctk.CTkButton(editor_frame, text="Save Query", command=save_selected_query).grid(row=0, column=2, padx=4)
ctk.CTkButton(editor_frame, text="Copy Selected", command=copy_selected_query).grid(row=0, column=3, padx=4)

# timestamp append controls
ts_frame = ctk.CTkFrame(bottom_frame)
ts_frame.grid(row=1, column=2, sticky="nsew", padx=(6,0))
ctk.CTkLabel(ts_frame, text="Timestamp (YYYY-MM-DD HH:MM:SS):").grid(row=0, column=0, sticky="w")
timestamp_input = ctk.CTkEntry(ts_frame)
timestamp_input.grid(row=0, column=1, sticky="ew", padx=(6,0))
ctk.CTkLabel(ts_frame, text="Minutes +/-").grid(row=1, column=0, sticky="w", pady=(6,0))
minutes_before_input = ctk.CTkEntry(ts_frame, width=80)
minutes_before_input.insert(0, "15")
minutes_before_input.grid(row=1, column=1, sticky="w", padx=(6,0))
ctk.CTkButton(ts_frame, text="Append Timestamp", command=append_timestamp_to_selected).grid(row=2, column=0, columnspan=2, pady=(6,0))

# status labels
query_status_label = ctk.CTkLabel(bottom_frame, text="", font=("Krub", 12))
query_status_label.grid(row=3, column=1, sticky="w", pady=(6,0))
query_copy_label = ctk.CTkLabel(bottom_frame, text="", font=("Krub", 12))
query_copy_label.grid(row=3, column=0, sticky="w", pady=(6,0))

# load persisted queries and refresh UI
load_saved_queries()
# if load_saved_queries replaced the list variable, ensure UI uses it
try:
    # reload saved_queries variable into listbox
    refresh_query_listbox()
except Exception:
    # if saved_queries was replaced unexpectedly, just refresh from it
    try:
        refresh_query_listbox()
    except Exception:
        pass

root.mainloop()
