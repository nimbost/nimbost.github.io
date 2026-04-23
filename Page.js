function log(msg) {
  const logs = document.getElementById("logs");
  logs.innerText += "\n> " + msg;
}

function runRecon() {
  const target = document.getElementById("target").value;

  if (!target) {
    log("No target entered.");
    return;
  }

  // Reset panels
  document.getElementById("dns").innerText = "Running...";
  document.getElementById("whois").innerText = "Running...";
  document.getElementById("ports").innerText = "Running...";
  document.getElementById("logs").innerText = "Starting ThreadT scan...\n";

  log("Target locked: " + target);

  // Simulated DNS
  setTimeout(() => {
    document.getElementById("dns").innerText =
      "A: 192.168.1.1\nMX: mail." + target + "\nNS: ns1." + target;
    log("DNS resolved.");
  }, 1000);

  // Simulated WHOIS
  setTimeout(() => {
    document.getElementById("whois").innerText =
      "Registrar: Demo Registrar\nCountry: Unknown\nCreated: 2020";
    log("WHOIS collected.");
  }, 2000);

  // Simulated Ports
  setTimeout(() => {
    document.getElementById("ports").innerText =
      "22 OPEN\n80 OPEN\n443 OPEN\n3306 CLOSED";
    log("Port scan complete.");
  }, 3000);

  setTimeout(() => {
    log("ThreadT scan finished.");
  }, 3500);
}