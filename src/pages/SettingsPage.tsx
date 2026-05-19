import { useState } from "react";
import { PageHeader, OverflowBreadcrumbs } from "@diligentcorp/atlas-react-bundle";
import { Button, Stack, Typography } from "@mui/material";
import { NavLink } from "react-router";

import PageLayout from "../components/PageLayout.js";
import { resetPrototypeCatalogAsync } from "../data/persistence/catalogStore.js";

export default function SettingsPage() {
  const [resetting, setResetting] = useState(false);

  return (
    <PageLayout>
      <PageHeader
        pageTitle="Settings"
        pageSubtitle="This is the app's settings"
        breadcrumbs={
          <OverflowBreadcrumbs
            leadingElement={<span>My App</span>}
            items={[
              {
                id: "settings",
                label: "Settings",
                url: "/",
              },
            ]}
            hideLastItem={true}
            aria-label="Breadcrumbs"
          >
            {({ label, url }) => <NavLink to={url}>{label}</NavLink>}
          </OverflowBreadcrumbs>
        }
      />
      <Stack sx={{ mt: 3, maxWidth: 560 }} gap={2}>
        <Typography variant="subtitle1">Prototype data</Typography>
        <Typography variant="body1" sx={{ color: "text.secondary" }}>
          Clear locally persisted catalog (threats, assessments, CRA draft, scenario edits), including IndexedDB
          if the catalog was stored there. After reload, the bundled prototype catalog loads again. In dev you
          can also open <code>/?resetCatalog=1</code> once instead of using this button.
        </Typography>
        <Button
          type="button"
          variant="outlined"
          disabled={resetting}
          onClick={async () => {
            setResetting(true);
            try {
              await resetPrototypeCatalogAsync();
            } finally {
              globalThis.location.reload();
            }
          }}
        >
          {resetting ? "Resetting…" : "Reset prototype data"}
        </Button>
      </Stack>
    </PageLayout>
  );
}
