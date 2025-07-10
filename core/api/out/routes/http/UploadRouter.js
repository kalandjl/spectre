"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var postgres_1 = require("../../lib/db/postgres");
var UploadRouter = function (req, res) {
    // Client uploads CSV
    // CSV is saved to database /raw_scans
    // DB trigger for /scans -> intel pipeline (prod)
    // Scan analysis is saved in /intel_scans and avaliable in front end dashboard
    try {
        var csv = JSON.parse(req.body.csv);
        (0, postgres_1.setDoc)('/raw_scans', {
            data: csv
        }, csv.scanId);
    }
    catch (e) {
        console.error("Exited due to error: ".concat(e));
    }
};
exports.default = UploadRouter;
