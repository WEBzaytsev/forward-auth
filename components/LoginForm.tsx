"use client";

import { Card } from "@heroui/react";
import { Lock } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

const TOTP_LENGTH = 6;

interface LoginFormProps {
  pinLength: number;
  redirectURL: string;
  totpEnabled: boolean;
}

export function LoginForm({
  pinLength,
  redirectURL,
  totpEnabled,
}: LoginFormProps) {
  const [pin, setPin] = useState<string[]>([]);
  const [totp, setTotp] = useState<string[]>([]);
  const [step, setStep] = useState<"pin" | "totp">("pin");
  const [error, setError] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isShaking, setIsShaking] = useState(false);
  const [isPending, setIsPending] = useState(false);
  const pinInputRef = useRef<HTMLInputElement>(null);
  const totpInputRef = useRef<HTMLInputElement>(null);

  const fail = useCallback((message: string) => {
    setErrorMessage(message);
    setError(true);
    setIsShaking(true);
    setTimeout(() => {
      setPin([]);
      setTotp([]);
      setStep("pin");
      setError(false);
      setIsShaking(false);
      setIsPending(false);
      pinInputRef.current?.focus();
    }, 500);
  }, []);

  const submit = useCallback(
    async (pinDigits: string[], totpDigits: string[]) => {
      if (isPending) return;
      setIsPending(true);
      setErrorMessage(null);

      try {
        const body: { pin: string; redirect: string; totp?: string } = {
          pin: pinDigits.join(""),
          redirect: redirectURL,
        };
        if (totpEnabled) {
          body.totp = totpDigits.join("");
        }

        const res = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });

        const data = (await res.json()) as { redirect?: string; error?: string };

        if (res.ok && data.redirect) {
          window.location.href = data.redirect;
          return;
        }

        fail(
          data.error ??
            (res.status === 429
              ? "Слишком много попыток. Подождите минуту"
              : "Неверный код. Проверьте ввод и попробуйте снова"),
        );
      } catch {
        fail(
          "Не удалось связаться с сервером. Проверьте подключение к интернету",
        );
      }
    },
    [fail, isPending, redirectURL, totpEnabled],
  );

  useEffect(() => {
    pinInputRef.current?.focus();
  }, []);

  useEffect(() => {
    if (step !== "pin" || pin.length < pinLength) return;

    if (totpEnabled) {
      setStep("totp");
      totpInputRef.current?.focus();
      return;
    }

    void submit(pin, []);
  }, [pin, pinLength, step, submit, totpEnabled]);

  useEffect(() => {
    if (step === "totp" && totp.length === TOTP_LENGTH) {
      void submit(pin, totp);
    }
  }, [pin, step, submit, totp]);

  useEffect(() => {
    const activeLength = step === "pin" ? pinLength : TOTP_LENGTH;
    const setDigits = step === "pin" ? setPin : setTotp;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (isPending) return;

      if (e.key >= "0" && e.key <= "9") {
        setErrorMessage(null);
        setDigits((prev) =>
          prev.length < activeLength ? [...prev, e.key] : prev,
        );
      } else if (e.key === "Backspace") {
        setErrorMessage(null);
        if (step === "totp" && totp.length === 0) {
          setStep("pin");
          setPin((prev) => prev.slice(0, -1));
          pinInputRef.current?.focus();
          return;
        }
        setDigits((prev) => prev.slice(0, -1));
      }
    };

    const handlePaste = (e: ClipboardEvent) => {
      e.preventDefault();
      if (isPending) return;
      const digits = (e.clipboardData?.getData("text") ?? "")
        .replace(/\D/g, "")
        .slice(0, activeLength);
      if (digits) setDigits(digits.split(""));
    };

    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("paste", handlePaste);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("paste", handlePaste);
    };
  }, [isPending, pin.length, pinLength, step, totp.length]);

  const activeLength = step === "pin" ? pinLength : TOTP_LENGTH;
  const activeDigits = step === "pin" ? pin : totp;
  const activeInputRef = step === "pin" ? pinInputRef : totpInputRef;

  const getSlotClass = (index: number) => {
    const isActive =
      index === activeDigits.length && activeDigits.length < activeLength;
    if (error) return "border-danger bg-danger/10";
    if (isActive) return "border-accent bg-accent/10 ring-2 ring-accent/30";
    if (activeDigits[index]) return "border-accent bg-accent/10";
    return "border-border bg-default";
  };

  const cardMaxWidth =
    activeLength <= 6 ? "max-w-sm" : activeLength <= 8 ? "max-w-md" : "max-w-lg";
  const slotSize =
    activeLength <= 5 ? "h-14 w-14" : activeLength <= 7 ? "h-12 w-12" : "h-10 w-10";
  const gapSize = activeLength <= 5 ? "gap-3" : "gap-2";

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className={`w-full ${cardMaxWidth}`}>
        <Card.Content className="p-8">
          <div className="mb-8 text-center">
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-accent/10">
              <Lock className="h-8 w-8 text-accent" />
            </div>
            <h1 className="mb-2 text-2xl font-bold text-foreground">
              Подтвердите доступ
            </h1>
            <p className="text-sm text-muted">
              {step === "pin"
                ? "Введите код доступа — после проверки откроется запрошенный сервис"
                : "Введите 6-значный код из приложения-аутентификатора"}
            </p>
          </div>

          <div
            className={`flex cursor-pointer justify-center ${gapSize} ${isShaking ? "animate-shake" : ""}`}
            onClick={() => activeInputRef.current?.focus()}
          >
            {Array.from({ length: activeLength }).map((_, index) => {
              const isActive =
                index === activeDigits.length && activeDigits.length < activeLength;
              return (
                <div
                  key={index}
                  className={`flex ${slotSize} items-center justify-center rounded-2xl border-2 transition-all ${getSlotClass(index)}`}
                >
                  {activeDigits[index] ? (
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

          <div className="mt-4 min-h-10 text-center text-sm" aria-live="polite">
            {isPending && !error && (
              <p className="text-muted">Проверяем код…</p>
            )}
            {errorMessage && (
              <p className="text-danger" role="alert">
                {errorMessage}
              </p>
            )}
          </div>

          <input
            ref={pinInputRef}
            type="text"
            inputMode="numeric"
            autoComplete="off"
            autoFocus
            aria-label="Код доступа"
            className="sr-only"
            value=""
            onChange={() => {}}
            tabIndex={step === "pin" ? 0 : -1}
          />
          <input
            ref={totpInputRef}
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            aria-label="Код подтверждения"
            className="sr-only"
            value=""
            onChange={() => {}}
            tabIndex={step === "totp" ? 0 : -1}
          />
        </Card.Content>
      </Card>
    </div>
  );
}
