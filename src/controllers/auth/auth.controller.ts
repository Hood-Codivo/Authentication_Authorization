import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { checkPassword, hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from "../../lib/token";
import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";
import * authenticator  from "otplib";



function getAppUrl() {
  return process.env.App_URL || `http://localhost:${process.env.PORT}`;
}

function getGoogleClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;

  if (!clientId || !clientSecret) {
    throw new Error("Google client and secret not found");
  }

  return new OAuth2Client({
    clientId,
    clientSecret,
    ...(redirectUri && { redirectUri }),
  });
}

export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data!",
        errors: result.error.flatten(),
      });
    }

    const { name, email, password } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res.status(409).json({
        message: "Email already in use!",
      });
    }
    const passwordHash = await hashPassword(password);
    const newlyCreatedUser = await User.create({
      name,
      email: normalizedEmail,
      passwordHash,
      role: "user",
      isEmailVerified: false,
      twoFactorEnabled: false,
    });

    // email verification part

    const verifyToken = jwt.sign(
      {
        sub: newlyCreatedUser.id,
      },
      process.env.JWT_ACCESS_SECRET!,
      {
        expiresIn: "1d",
      }
    );

    const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newlyCreatedUser.email,
      "Verify your email",
      `<p>Click the link below to verify your email:</p>
      <a href="${verifyUrl}">${verifyUrl}</a>
      <p>This link will expire in 24 hours.</p>`
    );

    return res.status(201).json({
      message: "User registered",
      user: {
        id: newlyCreatedUser.id,
        email: newlyCreatedUser.email,
        role: newlyCreatedUser.role,
        isEmailVerified: newlyCreatedUser.isEmailVerified,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.query.token as string | undefined;

  if (!token) {
    return res.status(400).json({ message: "Verification token is missing" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      sub: string;
    };
    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(400).json({
        message: "User not found",
      });
    }
    if (user.isEmailVerified) {
      return res.json({
        message: "Email is already verified",
      });
    }
    user.isEmailVerified = true;
    await user.save();

    return res.json({
      message: "Email is now verified, you can now login",
    });
  } catch (error) {
    console.error(error);
    return res.status(400).json({
      message: "Invalid or expired verification token",
    });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const result = loginSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data!",
        errors: result.error.flatten(),
      });
    }

    const { email, password, twoFactorCode } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(400).json({
        message: "Invalid email or password",
      });
    }

    if (!user.passwordHash) {
      return res.status(400).json({
        message:
          "This account uses Google sign-in. Please use Google to log in.",
      });
    }

    const isPasswordValid = await checkPassword(password, user.passwordHash);

    if (!isPasswordValid) {
      return res.status(400).json({
        message: "Invalid email or password",
      });
    }

    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: "Please verify your email before logging in",
      });
    }

    if(user.twoFactorEnabled){

      if(!twoFactorCode || typeof twoFactorCode){
        return res.status(400).json({
          message: "Two factor code is required"
        })
      }

      if(!user.twoFactorSecret){
        return res.status(400).json({
          message: "Two factor misconfigured"
        })
      }


    }

    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.json({
      message: "Login successful",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function refreshTokenHandler(req: Request, res: Response) {
  try {
    const token = req.cookies?.refreshToken as string | undefined;

    if (!token) {
      return res.status(401).json({ message: "Refresh token missing" });
    }

    const payload = verifyRefreshToken(token);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(401).json({ message: "user not found" });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: "refresh token invalidated" });
    }

    const newAccessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );

    const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      message: "Tokens refreshed successfully",
      accessToken: newAccessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function logOutHandler(req: Request, res: Response) {
  res.clearCookie("refreshToken", { path: "/" });

  return res.status(200).json({
    message: "Logged out successfully",
  });
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  if (!req.body) {
    return res.status(400).json({ message: "Request body is empty" });
  }

  const { email } = req.body as { email?: string };

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }
  const normalizedEmail = email.toLowerCase().trim();

  try {
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.json({
        message:
          "If an account with this email exists, a password reset link has been sent.",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");

    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await user.save();

    const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawToken}`;

    await sendEmail(
      user.email,
      "Reset your password",
      `<p>You have requested a password reset. Please click the link below to reset your password:</p>
      <p><a href="${resetUrl}">Reset Password ${resetUrl}</a></p>`
    );
    return res.json({
      message:
        "If an account with this email exists, a password reset link has been sent.",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  // Accept token from both query params and body
  let token =
    (req.body as { token?: string }).token || (req.query.token as string);
  const { password } = req.body as { password?: string };

  if (!token) {
    return res.status(400).json({ message: "Reset token is missing" });
  }
  if (!password || password.length < 6) {
    return res
      .status(400)
      .json({ message: "Password must be at least 6 characters long" });
  }

  try {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired reset token",
      });
    }

    const newPasswordHash = await hashPassword(password);

    user.passwordHash = newPasswordHash;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;

    user.tokenVersion = user.tokenVersion + 1;

    await user.save();

    return res.json({
      message: "Password has been reset successfully",
    });
  } catch (error) {
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function googleAuthStartHandler(req: Request, res: Response) {
  try {
    const client = getGoogleClient();

    const url = client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
    });

    return res.redirect(url);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function googleAuthCallbackHandler(req: Request, res: Response) {
  const code = req.query.code as string;

  if (!code) {
    return res.status(400).json({ message: "Authorization code missing" });
  }

  try {
    const client = getGoogleClient();

    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token!,
      audience: client._clientId!,
    });

    const payload = ticket.getPayload();

    if (!payload) {
      return res.status(400).json({ message: "Invalid token" });
    }

    const { email, name } = payload;

    if (!email) {
      return res.status(400).json({ message: "Email not provided by Google" });
    }

    const normalizedEmail = email.toLowerCase().trim();

    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      user = await User.create({
        name: name ?? null,
        email: normalizedEmail,
        role: "user",
        isEmailVerified: true,
        twoFactorEnabled: false,
      });
    }

    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.json({
      message: "Login successful",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function twoFASetuphandler(req: Request, res: Response) {
  const authReq = req as any;
  const authUser = authReq.user;

  if(!authUser){
    return res.status(401).json({
      message: 'Not authenticated'
    })
  }

  try {
    const user = await User.findById(authUser.id)

    if(!user){
      return res.status(404).json({
        message: "User not found",
      });
    }

    const secret = authenticator.generateSecret();

    const issuer = 'NodeAuth'
    

  } catch (error) {
    console.log(error)
    return res.status(500).json({
      message: "Internal server error",
    })
  }

}