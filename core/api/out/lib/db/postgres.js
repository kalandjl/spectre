"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setDoc = void 0;
// Sets a document 
var setDoc = function (collection, data, docId) {
    var doc_id = docId;
    if (!docId) {
        // doc_id = 
        // Initilize random doc key
    }
    console.log("Setting document ".concat(docId, " in collection ").concat(collection));
};
exports.setDoc = setDoc;
