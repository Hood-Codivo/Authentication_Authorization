import { Request, Response, Router } from "express";
import requireAuth from "../middleware/requireAuth";

const router = Router();

router.get("/me", requireAuth, async (req: Request, res: Response) => {
  const authReq = req as any;
  const authUser = authReq.user;

  return res.json({
    id: authUser.id,
    email: authUser.email,
    name: authUser.name,
    role: authUser.role,
    isEmailVerified: authUser.isEmailVerified,
  });
});

export default router;
