import { Router } from "express";
import {
  forgotPasswordHandler,
  googleAuthCallbackHandler,
  googleAuthStartHandler,
  loginHandler,
  logOutHandler,
  refreshTokenHandler,
  registerHandler,
  resetPasswordHandler,
  verifyEmailHandler,
} from "../controllers/auth/auth.controller";

const router = Router();

router.post("/register", registerHandler);
router.post("/login", loginHandler); // Assuming loginHandler is defined similarly to registerHandler
router.get("/verify-email", verifyEmailHandler);
router.post("/refresh", refreshTokenHandler);
router.post("/logout", logOutHandler);
router.post("/forgot-password", forgotPasswordHandler);
router.post("/reset-password", resetPasswordHandler); // Assuming a resetPasswordHandler exists
router.get("/google", googleAuthStartHandler);
router.get("/google/callback", googleAuthCallbackHandler);

export default router;
