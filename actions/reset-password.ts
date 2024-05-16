"use server";

import * as z from "zod";
import bcryptjs from "bcryptjs";
import { AuthError } from "next-auth";
import { ResetPasswordSchema } from "@/schemas";
import { getUserByEmail } from "@/data/users";
import { sendPasswordResetEmail } from "@/lib/mail";
import { generatePasswordResetToken } from "@/lib/tokens";
import { error } from "console";
import { getPasswordResetTokenByEmail, getPasswordResetTokenByToken } from "@/data/password-reset-token";
import { db } from "@/lib/db";

export const resetPassword = async (values: z.infer<typeof ResetPasswordSchema>, token?: string | null) => {
    if (!token){
        return { error: "Missing token!" };
    };
    
    const validatedFields = ResetPasswordSchema.safeParse(values);

    
    if (!validatedFields.success) {
        return {error: "Invalid fields!"};
    };

    const {password, confirm_password} = validatedFields.data;

    if (password !== confirm_password){
        return { error: "Password doesn't match!" };
    };

    const existingToken = await getPasswordResetTokenByToken(token);

    if(!existingToken){
        return {error: "Invalid token!"}
    }

    const hasExpired = new Date(existingToken.expires) < new Date();

    if (hasExpired) {
        return {error: "Token has expired!"}
    }

    const existingUser = await getUserByEmail(existingToken.email);

    if(!existingUser) {
        return { error: "Email doesn't exist" }
    }

    const hashedPassword = await bcryptjs.hash(password, 10);

    await db.user.update({
        where: {
            id: existingUser.id
        },
        data: {password: hashedPassword}
    });

    await db.passwordResetToken.delete({
        where: {id: existingToken.id}
    })

    return {success : "Password updated"};
}


