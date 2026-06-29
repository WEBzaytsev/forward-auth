import { Card } from "@heroui/react";
import Link from "next/link";

export default function NotFound() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="w-full max-w-sm">
        <Card.Content className="p-8 text-center">
          <h1 className="mb-2 text-2xl font-bold text-foreground">
            Страница не найдена
          </h1>
          <p className="mb-6 text-sm text-muted">
            Адрес удалён или введён с ошибкой. Если вы искали вход в сервис —
            начните с главной страницы.
          </p>
          <Link
            href="/"
            className="inline-flex h-10 w-full items-center justify-center rounded-lg border border-border bg-default px-4 text-sm font-medium text-foreground transition-colors hover:bg-default/80"
          >
            На главную
          </Link>
        </Card.Content>
      </Card>
    </div>
  );
}
