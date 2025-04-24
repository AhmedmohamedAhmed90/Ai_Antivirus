import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from main import scan_path, load_signatures, list_quarantine, restore_quarantined_file, load_quarantine_manifest
import threading
import queue

class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AI Antivirus")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", background="#2196F3")
        self.style.configure("TLabel", padding=6)
        self.style.configure("TFrame", background="#f0f0f0")
        
        # Create main container
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create scan section
        self.create_scan_section()
        
        # Create results section
        self.create_results_section()
        
        # Create quarantine section
        self.create_quarantine_section()
        
        # Load signatures
        self.signatures = load_signatures("signatures.db")
        
        # Queue for thread communication
        self.scan_queue = queue.Queue()
        
    def create_scan_section(self):
        scan_frame = ttk.LabelFrame(self.main_frame, text="Scan Options", padding="10")
        scan_frame.pack(fill=tk.X, pady=5)
        
        # Path selection
        path_frame = ttk.Frame(scan_frame)
        path_frame.pack(fill=tk.X, pady=5)
        
        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.path_var)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        browse_btn = ttk.Button(path_frame, text="Browse", command=self.browse_path)
        browse_btn.pack(side=tk.RIGHT)
        
        # Action selection
        action_frame = ttk.Frame(scan_frame)
        action_frame.pack(fill=tk.X, pady=5)
        
        self.action_var = tk.StringVar(value="report")
        ttk.Radiobutton(action_frame, text="Report Only", variable=self.action_var, value="report").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(action_frame, text="Quarantine", variable=self.action_var, value="quarantine").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(action_frame, text="Remove", variable=self.action_var, value="remove").pack(side=tk.LEFT, padx=5)
        
        # Scan button
        scan_btn = ttk.Button(scan_frame, text="Start Scan", command=self.start_scan)
        scan_btn.pack(pady=5)
        
    def create_results_section(self):
        results_frame = ttk.LabelFrame(self.main_frame, text="Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
    def create_quarantine_section(self):
        quarantine_frame = ttk.LabelFrame(self.main_frame, text="Quarantine Management", padding="10")
        quarantine_frame.pack(fill=tk.X, pady=5)
        
        self.quarantine_listbox = tk.Listbox(quarantine_frame, height=5)
        self.quarantine_listbox.pack(fill=tk.X, pady=5)
        
        btn_frame = ttk.Frame(quarantine_frame)
        btn_frame.pack(fill=tk.X)
        
        refresh_btn = ttk.Button(btn_frame, text="Refresh", command=self.refresh_quarantine)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        restore_btn = ttk.Button(btn_frame, text="Restore Selected", command=self.restore_selected)
        restore_btn.pack(side=tk.LEFT, padx=5)
        
        self.refresh_quarantine()
        
    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.path_var.set(path)
            
    def start_scan(self):
        path = self.path_var.get()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Please select a valid path to scan")
            return
            
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Starting scan of: {path}\n")
        
        # Start scan in a separate thread
        scan_thread = threading.Thread(
            target=self.run_scan,
            args=(path, self.action_var.get())
        )
        scan_thread.daemon = True
        scan_thread.start()
        
    def run_scan(self, path, action):
        def update_results(message):
            self.scan_queue.put(message)
            
        def process_queue():
            while not self.scan_queue.empty():
                message = self.scan_queue.get()
                self.results_text.insert(tk.END, message + "\n")
                self.results_text.see(tk.END)
            self.root.after(100, process_queue)
            
        self.root.after(100, process_queue)
        scan_path(path, self.signatures, action)
        self.scan_queue.put("Scan completed!")
        self.refresh_quarantine()
        
    def refresh_quarantine(self):
        self.quarantine_listbox.delete(0, tk.END)
        try:
            manifest = load_quarantine_manifest()
            if not manifest:
                self.quarantine_listbox.insert(tk.END, "Quarantine is empty")
                return
                
            for qid, item in manifest.items():
                display_text = f"{item.get('original_path', 'N/A')} - {item.get('reason', 'N/A')}"
                self.quarantine_listbox.insert(tk.END, display_text)
        except Exception as e:
            self.quarantine_listbox.insert(tk.END, f"Error loading quarantine: {str(e)}")
            
    def restore_selected(self):
        selection = self.quarantine_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file to restore")
            return
            
        index = selection[0]
        quarantined_files = list_quarantine()
        if 0 <= index < len(quarantined_files):
            file_info = quarantined_files[index]
            try:
                restore_quarantined_file(file_info['id'])
                messagebox.showinfo("Success", f"File restored: {file_info['original_path']}")
                self.refresh_quarantine()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to restore file: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop() 