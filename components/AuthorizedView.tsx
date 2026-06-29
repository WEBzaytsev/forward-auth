"use client";

import { Button, Card } from "@heroui/react";
import { ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

export function AuthorizedView() {
  const router = useRouter();
  const [isPending, setIsPending] = useState(false);

  const handleLogout = async () => {
    setIsPending(true);
    try {
      await fetch("/api/logout", { method: "POST" });
    } finally {
      router.push("/");
      router.refresh();
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="w-full max-w-sm">
        <Card.Content className="p-8 text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-success/10">
            <ShieldCheck className="h-8 w-8 text-success" />
          </div>
          <h1 className="mb-2 text-2xl font-bold text-foreground">Доступ открыт</h1>
          <p className="mb-6 text-sm text-muted">
            Сессия активна на этом устройстве. Защищённые сервисы открываются без
            повторного ввода кода.
          </p>
          <Button
            variant="outline"
            fullWidth
            isPending={isPending}
            onPress={handleLogout}
          >
            {({ isPending: p }) => (p ? "Выход…" : "Выйти")}
          </Button>
        </Card.Content>
      </Card>
    </div>
  );
}
