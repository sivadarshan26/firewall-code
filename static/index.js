function showToast(message) {
    const toast = document.createElement("div");
    toast.className = "toast show";
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.classList.remove("show");
      setTimeout(() => document.body.removeChild(toast), 300);
    }, 2000);
  }
  
  function fetchAccessLogs() {
    fetch("/api/access_logs")
      .then((response) => response.json())
      .then((data) => {
        const logList = document.getElementById("access-list");
        logList.innerHTML = "";
  
        data.forEach((log) => {
          const item = document.createElement("li");
          item.className = "text-xs px-2 py-1 border-l-2";
          if (log.includes("[BLOCK]"))
            item.classList.add("border-red-500", "text-red-400");
          else if (
            log.includes("[UNBLOCK]") ||
            log.includes("[LIMIT REMOVED]")
          )
            item.classList.add("border-green-500", "text-green-400");
          else if (log.includes("[HTTP]"))
            item.classList.add("border-yellow-500", "text-yellow-400");
          else if (log.includes("[ACCESS]"))
            item.classList.add("border-cyan-500", "text-cyan-400");
          else item.classList.add("border-gray-600", "text-gray-400");
  
          item.textContent = log;
          logList.appendChild(item);
        });
      });
  }
  
  function fetchSniffedPorts() {
    fetch("/api/sniffed_ports")
      .then((response) => response.json())
      .then((data) => {
        const snifferList = document.getElementById("sniffer-list");
        snifferList.innerHTML = "";
        data.forEach((port) => {
          const li = document.createElement("li");
          li.className = "flex justify-between items-center";
  
          const span = document.createElement("span");
          span.textContent = "Port " + port;
          span.className = "text-cyan-400 text-sm";
  
          const button = document.createElement("button");
          button.textContent = "✖";
          button.className = "text-xs text-red-400 hover:text-red-600";
          button.title = "Stop Sniffer";
          button.onclick = (e) => {
            e.preventDefault();
            fetch("/api/stop_sniffer", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ sniff_port: port }),
            }).then((res) => {
              if (res.ok) {
                showToast("Sniffer stopped on port " + port);
                fetchSniffedPorts();
              }
            });
          };
  
          li.appendChild(span);
          li.appendChild(button);
          snifferList.appendChild(li);
        });
      });
  }
  
  function handleActions() {
    document.getElementById("block-form").onsubmit = (e) => {
      e.preventDefault();
      const port = e.target.port.value;
      fetch("/api/block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ port }),
      }).then((res) => {
        if (res.ok) {
          showToast("Port blocked: " + port);
          e.target.reset();
          location.reload();
        }
      });
    };
  
    document.querySelectorAll("#unblock-buttons button").forEach((btn) => {
      btn.onclick = (e) => {
        e.preventDefault();
        const port = btn.dataset.port;
        fetch("/api/unblock", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ port }),
        }).then((res) => {
          if (res.ok) {
            showToast("Unblocked: " + port);
            location.reload();
          }
        });
      };
    });
  
    
    document.getElementById('limit-form').addEventListener('submit', async function (e) {
      e.preventDefault();
    
      const form = e.target;
      const port = parseInt(form.port.value);
      const mode = form.mode.value;
    
      let payload = { port, mode };
    
      if (mode === 'scheme') {
        payload.scheme = form.scheme.value;
      } else {
        payload.rate = parseInt(form.rate.value);
        payload.unit = form.unit.value;
      }
    
      const res = await fetch('/api/set_limit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    
      const data = await res.json();
      showToast(data.success ? '✅ Limit Set!' : '❌ Failed to set limit');
    });
    
    
    // Toggle field visibility
    document.querySelectorAll("input[name='mode']").forEach((radio) =>
      radio.addEventListener("change", (e) => {
        const customFields = document.getElementById("custom-fields");
        const schemeFields = document.getElementById("scheme-fields");
        if (e.target.value === "custom") {
          customFields.classList.remove("hidden");
          schemeFields.classList.add("hidden");
        } else {
          customFields.classList.add("hidden");
          schemeFields.classList.remove("hidden");
        }
      })
    );
    
  
    document.getElementById("sniffer-form").onsubmit = (e) => {
      e.preventDefault();
      const sniff_port = e.target.sniff_port.value;
      fetch("/api/start_sniffer", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sniff_port }),
      }).then((res) => {
        if (res.ok) {
          showToast("Sniffer started on port " + sniff_port);
          e.target.reset();
          fetchSniffedPorts();
        }
      });
    };
  
    document.querySelectorAll("[data-remove-limit]").forEach((btn) => {
      btn.onclick = (e) => {
        e.preventDefault();
        const port = btn.dataset.removeLimit;
        fetch("/api/remove_limit", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ port }), // port is sent in JSON
        })
        .then((res) => {
          if (res.ok) {
            showToast("Rate limit removed on port " + port);
            location.reload();
          }
        });
      };
    });
  }

  function fetchRateLimits() {
    fetch("/api/rate_limits")
      .then((res) => res.json())
      .then((data) => {
        const rateLimitList = document.querySelector(
          "div.border-purple-500 ul"
        );
        rateLimitList.innerHTML = "";
        for (const port in data) {
          const li = document.createElement("li");
          li.className = "flex justify-between items-center";
  
          const span = document.createElement("span");
          span.innerHTML = `Port ${port} → <span class="text-gray-300">${data[port]}</span>`;
  
          const btn = document.createElement("button");
          btn.dataset.removeLimit = port;
          btn.title = "Remove Limit";
          btn.className = "text-red-400 hover:text-red-600 text-xs";
          btn.textContent = "✖";
  
          btn.onclick = (e) => {
            e.preventDefault();
            fetch("/api/remove_limit", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ port }),
            }).then((res) => {
              if (res.ok) {
                showToast("Rate limit removed on port " + port);
                fetchRateLimits(); // refresh again
              }
            });
          };
  
          li.appendChild(span);
          li.appendChild(btn);
          rateLimitList.appendChild(li);
        }
      });
  }
  
  setInterval(fetchRateLimits, 3000);
  window.onload = () => {
    fetchAccessLogs();
    fetchSniffedPorts();
    fetchRateLimits(); // <- include this too
    handleActions();
  };
  