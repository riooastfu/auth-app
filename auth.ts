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
  pages:{
    signIn: "/auth/login",
    error: "/auth/error",
  },
  events:{
    async linkAccount({user}) {
        await db.user.update({
          where: {id: user.id},
          data: {emailVerified: new Date()}
        })
    },
  },
  callbacks: {
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