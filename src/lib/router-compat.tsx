"use client";
/**
 * Drop-in compatibility shim: re-exports Next.js navigation primitives with
 * the same API surface as react-router-dom so existing page and component
 * files only need their import path changed.
 *
 * Covered: useNavigate, useLocation, useSearchParams, useParams, Link, NavLink
 */
import React, { useCallback } from "react";
import {
  useRouter,
  usePathname,
  useSearchParams as useNextSearchParams,
  useParams as useNextParams,
} from "next/navigation";
import NextLink from "next/link";
import type { LinkProps as NextLinkProps } from "next/link";

// ── useNavigate ──────────────────────────────────────────────────────────────

type NavigateOptions = { replace?: boolean; state?: unknown };

export function useNavigate() {
  const router = useRouter();
  return useCallback(
    (to: string | number, options?: NavigateOptions) => {
      if (typeof to === "number") {
        if (to < 0) router.back();
        else router.forward();
        return;
      }
      if (options?.replace) {
        router.replace(to);
      } else {
        router.push(to);
      }
    },
    [router]
  );
}

// ── useLocation ──────────────────────────────────────────────────────────────

export function useLocation() {
  const pathname = usePathname();
  const searchParams = useNextSearchParams();
  const search = searchParams.toString() ? `?${searchParams.toString()}` : "";
  return { pathname, search, hash: "", state: null, key: "default" };
}

// ── useSearchParams ───────────────────────────────────────────────────────────
// Returns [params, setParams] matching react-router-dom tuple signature.

export function useSearchParams(): [
  URLSearchParams,
  (
    next: URLSearchParams | Record<string, string> | ((prev: URLSearchParams) => URLSearchParams),
    options?: { replace?: boolean }
  ) => void
] {
  const raw = useNextSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  const params = new URLSearchParams(raw.toString());

  const setParams = useCallback(
    (
      next:
        | URLSearchParams
        | Record<string, string>
        | ((prev: URLSearchParams) => URLSearchParams),
      options?: { replace?: boolean }
    ) => {
      const current = new URLSearchParams(raw.toString());
      let updated: URLSearchParams;
      if (typeof next === "function") {
        updated = next(current);
      } else if (next instanceof URLSearchParams) {
        updated = next;
      } else {
        Object.entries(next).forEach(([k, v]) => current.set(k, v));
        updated = current;
      }
      const url = `${pathname}?${updated.toString()}`;
      if (options?.replace) {
        router.replace(url);
      } else {
        router.push(url);
      }
    },
    [raw, router, pathname]
  );

  return [params, setParams];
}

// ── useParams ────────────────────────────────────────────────────────────────

export function useParams<T extends Record<string, string>>(): T {
  return useNextParams() as T;
}

// ── Link ─────────────────────────────────────────────────────────────────────
// react-router uses `to`; next/link uses `href`. Bridge both.

interface LinkProps extends Omit<NextLinkProps, "href"> {
  to?: string;
  href?: string;
  children?: React.ReactNode;
  className?: string;
}

export function Link({ to, href, children, ...rest }: LinkProps) {
  return (
    <NextLink href={(to ?? href ?? "") as string} {...rest}>
      {children}
    </NextLink>
  );
}

// ── NavLink ───────────────────────────────────────────────────────────────────

interface NavLinkProps extends Omit<NextLinkProps, "href"> {
  to: string;
  end?: boolean;
  className?: string | ((props: { isActive: boolean }) => string);
  children?: React.ReactNode | ((props: { isActive: boolean }) => React.ReactNode);
}

export function NavLink({ to, end, className, children, ...rest }: NavLinkProps) {
  const pathname = usePathname();
  const isActive = end ? pathname === to : pathname.startsWith(to);
  const resolvedClass =
    typeof className === "function" ? className({ isActive }) : className;
  const resolvedChildren =
    typeof children === "function" ? children({ isActive }) : children;
  return (
    <NextLink href={to} className={resolvedClass} {...rest}>
      {resolvedChildren}
    </NextLink>
  );
}

// ── Re-export anything else callers might destructure ─────────────────────────
// (Routes, Route, BrowserRouter are App.tsx-only and will be deleted)
export default {};
