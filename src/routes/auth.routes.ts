import { Router } from "express";
import {
  loginHandler,
  logOutHandler,
  refreshTokenHandler,
  registerHandler,
  verifyEmailHandler,
} from "../controllers/auth/auth.controller";

const router = Router();

router.post("/register", registerHandler);
router.post("/login", loginHandler); // Assuming loginHandler is defined similarly to registerHandler
router.get("/verify-email", verifyEmailHandler);
router.post("/refresh", refreshTokenHandler);
router.post("/logout", logOutHandler);

export default router;
