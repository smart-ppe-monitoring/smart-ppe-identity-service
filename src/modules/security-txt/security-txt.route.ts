import { Router } from "express";
import { securityTxtController } from "./security-txt.controller";
import { SECURITY_TXT_PATHS } from "../../common/constants/security-txt.constant";

const router = Router();

// Endpoint chính thức theo chuẩn IETF RFC 9116
router.get(SECURITY_TXT_PATHS.WELL_KNOWN, securityTxtController.getSecurityTxt);

// Endpoint tương thích cũ chuyển hướng sang đường dẫn chính thức (Mục 3 RFC 9116)
router.get(SECURITY_TXT_PATHS.LEGACY, securityTxtController.redirectLegacy);

export default router;
