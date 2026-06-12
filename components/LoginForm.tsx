"use client";

import { Card } from "@heroui/react";
import { Lock } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

interface LoginFormProps {
  pinLength: number;
  redirectURL: string;
}

export function LoginForm({ pinLength, redirectURL }: LoginFormProps) {
  const [pin, setPin] = useState<string[]>([]);
  const [error, setError] = useState(false);
  const [isShaking, setIsShaking] = useState(false);
  const [isPending, setIsPending] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const submit = useCallback(
    async (digits: string[]) => {
      if (isPending) return;
      setIsPending(true);

      try {
        const res = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pin: digits.join(""), redirect: redirectURL }),
        });

        if (res.ok) {
          const data = (await res.json()) as { redirect: string };
          window.location.href = data.redirect;
          return;
        }
      } catch {
        // network error — fall through to shake
      }

      setError(true);
      setIsShaking(true);
      setTimeout(() => {
        setPin([]);
        setError(false);
        setIsShaking(false);
        setIsPending(false);
        inputRef.current?.focus();
      }, 500);
    },
    [isPending, redirectURL],
  );

  useEffect(() => {
    if (pin.length === pinLength) {
      void submit(pin);
    }
  }, [pin, pinLength, submit]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (isPending) return;
      if (e.key >= "0" && e.key <= "9") {
        setPin((prev) => (prev.length < pinLength ? [...prev, e.key] : prev));
      } else if (e.key === "Backspace") {
        setPin((prev) => prev.slice(0, -1));
      }
    };

    const handlePaste = (e: ClipboardEvent) => {
      e.preventDefault();
      if (isPending) return;
      const digits = (e.clipboardData?.getData("text") ?? "")
        .replace(/\D/g, "")
        .slice(0, pinLength);
      if (digits) setPin(digits.split(""));
    };

    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("paste", handlePaste);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("paste", handlePaste);
    };
  }, [isPending, pinLength]);

  const getSlotClass = (index: number) => {
    const isActive = index === pin.length && pin.length < pinLength;
    if (error) return "border-danger bg-danger/10";
    if (isActive) return "border-accent bg-accent/10 ring-2 ring-accent/30";
    if (pin[index]) return "border-accent bg-accent/10";
    return "border-border bg-default";
  };

  const cardMaxWidth =
    pinLength <= 6 ? "max-w-sm" : pinLength <= 8 ? "max-w-md" : "max-w-lg";
  const slotSize =
    pinLength <= 5 ? "h-14 w-14" : pinLength <= 7 ? "h-12 w-12" : "h-10 w-10";
  const gapSize = pinLength <= 5 ? "gap-3" : "gap-2";

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className={`w-full ${cardMaxWidth}`}>
        <Card.Content className="p-8">
          <div className="mb-8 text-center">
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-accent/10">
              <Lock className="h-8 w-8 text-accent" />
            </div>
            <h1 className="mb-2 text-2xl font-bold text-foreground">Здравствуйте!</h1>
            <p className="text-sm text-muted">Введите PIN-код</p>
          </div>

          <div
            className={`flex cursor-pointer justify-center ${gapSize} ${isShaking ? "animate-shake" : ""}`}
            onClick={() => inputRef.current?.focus()}
          >
            {Array.from({ length: pinLength }).map((_, index) => {
              const isActive = index === pin.length && pin.length < pinLength;
              return (
                <div
                  key={index}
                  className={`flex ${slotSize} items-center justify-center rounded-2xl border-2 transition-all ${getSlotClass(index)}`}
                >
                  {pin[index] ? (
                    <div
                      className={`h-3 w-3 rounded-full ${error ? "bg-danger" : "bg-accent"}`}
                    />
                  ) : (
                    isActive && (
                      <div className="animate-blink h-6 w-0.5 bg-accent" />
                    )
                  )}
                </div>
              );
            })}
          </div>

          <input
            ref={inputRef}
            type="text"
            inputMode="numeric"
            autoComplete="off"
            autoFocus
            className="sr-only"
            value=""
            onChange={() => {}}
          />
        </Card.Content>
      </Card>
    </div>
  );
}
