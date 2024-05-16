import bcryptjs from "bcryptjs";
import NextAuth from "next-auth";
import { PrismaAdapter } from "@auth/prisma-adapter";

import { db } from "@/lib/db";
import authConfig from "./auth.config";
import { getUserById } from "./data/users";
import { UserRole } from "@prisma/client";

declare module "next-auth" {
  interface User {
    // Add your additional properties here:
    role: UserRole
  }
}

declare module "@auth/core/adapters" {
  interface AdapterUser {
    // Add your additional properties here:
    role: UserRole
  }
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  pages: {
    signIn: "/auth/login",
    error: "/auth/error",
  },
  events: {
    async linkAccount({ user }) {
      await db.user.update({
        where: { id: user.id },
        data: { emailVerified: new Date() }
      })
    },
  },
  callbacks: {
    async signIn({ user, account }) {

      // Allow OAuth without email verification
      if (account?.provider !== "credentials") return true;

      //Prevent sign in without email verification
      const existingUser = await getUserById(user.id!);

      if (!existingUser?.emailVerified) return false;

      //TODO: ADD 2FA check

      return true
    },
    async session({ token, session }) {
      if (token.sub && session.user) {
        session.user.id = token.sub;
      }

      if (token.role && session.user) {
        session.user.role = token.role as UserRole;
      }

      return session;
    },
    async jwt({ token }) {
      if (!token.sub) return token;

      const existingUser = await getUserById(token.sub);

      if (!existingUser) return token;

      token.role = existingUser.role;

      return token;
    },
  },
  adapter: PrismaAdapter(db),
  session: { strategy: "jwt" },
  ...authConfig,
})