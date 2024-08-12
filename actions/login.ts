"use server";

import * as z from "zod";
import { AuthError } from "next-auth";

import { signIn } from "@/auth";
import { LoginSchema } from "@/schemas";
import { getUserByEmail } from "@/data/user";
import { getTwoFactorTokenByEmail } from "@/data/two-factor-token";
import { sendVerificationEmail, sendTwoFactorTokenEmail } from "@/lib/mail";

import { DEFAULT_LOGIN_REDIRECT } from "@/routes";
import {
  generateVerificationToken,
  generateTwoFactorToken,
} from "@/lib/tokens";
import { db } from "@/lib/db";
import { getTwoFactorConfirmationbyUserId } from "@/data/tow-factor-confirmation";

export const login = async (
  values: z.infer<typeof LoginSchema>,
  callbackUrl?: string | null
) => {
  const validatedFields = LoginSchema.safeParse(values);

  if (!validatedFields.success) {
    return { error: "Invalid fileds" };
  }

  const { email, password, code } = validatedFields.data;

  const existingUser = await getUserByEmail(email);

  if (!existingUser || !existingUser.email || !existingUser.password) {
    return { error: "Email does not exist" };
  }

  if (!existingUser.emailVerified) {
    const verificationToken = await generateVerificationToken(
      existingUser.email
    );

    await sendVerificationEmail(
      verificationToken.email,
      verificationToken.token
    );

    return { success: "Confirmation email sent" };
  }

  if (existingUser.isTwoFactorEnabled && existingUser.email) {
    if (code) {
      //TODO. Verify code
      const TwoFactorToken = await getTwoFactorTokenByEmail(existingUser.email);
      if (!TwoFactorToken) {
        return { error: "Invalid code!" };
      }

      if (TwoFactorToken.token !== code) {
        return { error: "Invalid code!" };
      }
      const hasExpired = new Date(TwoFactorToken.expires) < new Date();

      if (hasExpired) {
        return { error: "Code expired" };
      }

      await db.twoFactorToken.delete({
        where: { id: TwoFactorToken.id },
      });

      const existingconfirmation = await getTwoFactorConfirmationbyUserId(
        existingUser.id
      );

      if (existingconfirmation) {
        await db.twoFactorConfirmation.delete({
          where: {
            id: existingconfirmation.id,
          },
        });
      }

      await db.twoFactorConfirmation.create({
        data: {
          userId: existingUser.id,
        },
      });
    } else {
      const twoFactorToken = await generateTwoFactorToken(existingUser.email);
      await sendTwoFactorTokenEmail(twoFactorToken.email, twoFactorToken.token);
      return { twoFactor: true };
    }
  }

  try {
    await signIn("credentials", {
      email,
      password,
      redirectTo: callbackUrl || DEFAULT_LOGIN_REDIRECT,
    });
  } catch (error) {
    if (error instanceof AuthError) {
      switch (error.type) {
        case "CredentialsSignin":
          return { error: "Invalid credentials" };
        default:
          return { error: "Something went wrong" };
      }
    }
    throw error;
  }
};
