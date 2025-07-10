
// Sets a document 
export const setDoc = (collection: string, data: {[x:string]: any}, docId?: string) => {


    let doc_id = docId
    
    if (!docId) {
        // doc_id = 
        // Initilize random doc key
    }

    console.log(`Setting document ${docId} in collection ${collection}`)
}
