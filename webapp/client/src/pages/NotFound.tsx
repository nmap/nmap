import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { AlertCircle, Home } from "lucide-react";
import { useLocation } from "wouter";

export default function NotFound() {
  const [, setLocation] = useLocation();

  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <Card className="w-full max-w-md border-border/50 bg-card/80 backdrop-blur-sm">
        <CardContent className="pt-8 pb-8 text-center">
          <div className="flex justify-center mb-6">
            <div className="relative">
              <div className="absolute inset-0 bg-red-500/10 rounded-full animate-pulse" />
              <AlertCircle className="relative h-14 w-14 text-red-400" />
            </div>
          </div>
          <h1 className="text-4xl font-bold text-foreground font-[Outfit] mb-2">404</h1>
          <h2 className="text-lg font-semibold text-muted-foreground mb-4">
            Page Not Found
          </h2>
          <p className="text-sm text-muted-foreground mb-8">
            The requested resource does not exist or has been moved.
          </p>
          <Button
            onClick={() => setLocation("/")}
            className="bg-purple-600 hover:bg-purple-700 text-white gap-2"
          >
            <Home className="w-4 h-4" />
            Return to Command Center
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
