const API = "http://127.0.0.1:5000";

async function call(action, extra = {}) {
  const response = await fetch(`${API}/api/control`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({action, ...extra})
  });
  if (!response.ok) throw new Error((await response.json()).message || "控制失败");
}

async function refresh() {
  try {
    const data = await (await fetch(`${API}/api/traffic`)).json();
    document.querySelector("#qps").textContent = data.qps;
    document.querySelector("#packets").textContent = data.packet_count;
    document.querySelector("#ports").textContent = data.port_count;
    document.querySelector("#status").textContent = data.alert ? "异常" : "正常";
    document.querySelector("#error").textContent = data.error || "";
  } catch (error) {
    document.querySelector("#error").textContent = "Agent 未运行";
  }
}

async function loadInterfaces() {
  try {
    const data = await (await fetch(`${API}/api/interfaces`)).json();
    for (const name of data.interfaces || []) {
      const option = document.createElement("option");
      option.value = name; option.textContent = name;
      document.querySelector("#interfaces").appendChild(option);
    }
  } catch (_) {}
}

document.querySelector("#capture").onclick = async () => {
  try { await call("start_capture", {interface: document.querySelector("#interfaces").value}); await refresh(); }
  catch (error) { document.querySelector("#error").textContent = error.message; }
};
document.querySelector("#simulate").onclick = async () => { await call("start_simulation"); await refresh(); };
document.querySelector("#stop").onclick = async () => { await call("stop"); await refresh(); };
document.querySelector("#dashboard").onclick = () => chrome.tabs.create({url: `${API}/`});
loadInterfaces();
refresh();
setInterval(refresh, 1000);
