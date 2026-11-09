(function () {
  "use strict";

  var inputEl = document.getElementById("plan");
  var resultsEl = document.getElementById("results");
  var statusEl = document.getElementById("status");
  var evaluateBtn = document.getElementById("evaluate");
  var sampleBtn = document.getElementById("load-sample");
  var clearBtn = document.getElementById("clear");

  var SAMPLE = {
    format_version: "1.2",
    terraform_version: "1.9.0",
    resource_changes: [
      {
        address: "aws_s3_bucket.public",
        mode: "managed",
        type: "aws_s3_bucket",
        name: "public",
        change: {
          actions: ["create"],
          before: null,
          after: { bucket: "demo-public-logs", acl: "public-read", tags: { Name: "public" } },
        },
      },
      {
        address: "aws_security_group.wide_open",
        mode: "managed",
        type: "aws_security_group",
        name: "wide_open",
        change: {
          actions: ["create"],
          before: null,
          after: {
            name: "wide-open",
            ingress: [
              { from_port: 22, to_port: 22, protocol: "tcp", cidr_blocks: ["0.0.0.0/0"], ipv6_cidr_blocks: [] },
            ],
            tags: { Environment: "dev" },
          },
        },
      },
      {
        address: "aws_db_instance.main",
        mode: "managed",
        type: "aws_db_instance",
        name: "main",
        change: {
          actions: ["create"],
          before: null,
          after: { engine: "postgres", storage_encrypted: false, tags: { Owner: "alice", Environment: "prod" } },
        },
      },
    ],
  };

  function renderFindings(result) {
    resultsEl.innerHTML = "";
    var all = []
      .concat(
        result.deny.map(function (f) {
          return f;
        })
      )
      .concat(
        result.warn.map(function (f) {
          return f;
        })
      );

    if (!all.length) {
      var ok = document.createElement("div");
      ok.className = "empty";
      ok.textContent = "No findings. Plan looks clean for the bundled rules.";
      resultsEl.appendChild(ok);
      statusEl.textContent = "0 denies, 0 warns";
      return;
    }

    all.forEach(function (f) {
      var el = document.createElement("article");
      el.className = "finding " + (f.severity === "high" ? "high" : "low");
      el.innerHTML =
        '<div><span class="id"></span><span class="sev"></span></div>' +
        '<div class="res"></div>' +
        '<div class="msg"></div>';
      el.querySelector(".id").textContent = f.id;
      el.querySelector(".sev").textContent = f.severity;
      el.querySelector(".res").textContent = f.resource;
      el.querySelector(".msg").textContent = f.msg.replace(/^\[[^\]]+\] \([^)]+\) [^:]+: /, "");
      resultsEl.appendChild(el);
    });

    statusEl.textContent = result.deny.length + " denies, " + result.warn.length + " warns";
  }

  function run() {
    statusEl.textContent = "";
    var raw = inputEl.value.trim();
    if (!raw) {
      resultsEl.innerHTML = '<div class="error">Paste a terraform show -json plan document.</div>';
      return;
    }
    var plan;
    try {
      plan = JSON.parse(raw);
    } catch (err) {
      resultsEl.textContent = "";
      var errEl = document.createElement("div");
      errEl.className = "error";
      errEl.textContent = "Invalid JSON: " + String(err.message || err);
      resultsEl.appendChild(errEl);
      return;
    }
    var result = window.TfPolicyPack.evaluate(plan);
    renderFindings(result);
  }

  evaluateBtn.addEventListener("click", run);
  sampleBtn.addEventListener("click", function () {
    inputEl.value = JSON.stringify(SAMPLE, null, 2);
    run();
  });
  clearBtn.addEventListener("click", function () {
    inputEl.value = "";
    resultsEl.innerHTML = "";
    statusEl.textContent = "";
  });
})();
