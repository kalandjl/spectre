import { Request, Response } from "express";
import { setDoc } from "../../lib/db/postgres";

const UploadRouter = (req: Request, res: Response) => {

    // Client uploads CSV
    // CSV is saved to database /raw_scans
    // DB trigger for /scans -> intel pipeline (prod)
    // Scan analysis is saved in /intel_scans and avaliable in front end dashboard

    try {
        const csv = JSON.parse(req.body.csv)

        setDoc('/raw_scans', {
            data: csv
        }, 
        csv.scanId)
        
    } catch (e) {
        console.error(`Exited due to error: ${e}`)
    }
}

export default UploadRouter

