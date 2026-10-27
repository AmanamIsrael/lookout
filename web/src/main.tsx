import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ApiError } from "./api";
import { App } from "./app";
import "./index.css";

// Any 401 means the session ended: drop cached data and show the login form.
const onError = (err: unknown) => {
  if (err instanceof ApiError && err.status === 401) {
    queryClient.setQueryData(["session"], { authenticated: false });
  }
};

const queryClient: QueryClient = new QueryClient({
  queryCache: new QueryCache({ onError }),
  mutationCache: new MutationCache({ onError }),
  defaultOptions: { queries: { retry: (n, err) => !(err instanceof ApiError && err.status < 500) && n < 2 } },
});

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </StrictMode>,
  );
}
