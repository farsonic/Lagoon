/*
 * Lagoon - the MUI front end (src/mui): one source for the Amiga (MUI 3.8) and the classic Mac
 * OS (Riptide's MUI for the Mac, riptide src/mac/mui). What a platform supplies:
 *   - main(), which opens what it needs (muimaster.library and locale.library on the Amiga; the
 *     Mac's MUI and Riptide's socket interface on the Mac) and calls lm_gui_run();
 *   - the AmigaDOS calls the front end makes for local files (Open, Read, Write, Close, Lock,
 *     CreateDir, AddPart): the Amiga's own, or riptide's src/mac/mui/mm_os.c on the Mac;
 *   - ln_sys.h and ln_net.h for the core (src/amiga, src/mac).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LM_GUI_H
#define LM_GUI_H

/* the application's MUI object tree runs until the main window closes; 0 or an error code */
int lm_gui_run(void);

/* the catalog (lm_strings.h), opened by lm_gui_run on the Amiga */
const char *lm_str(int id);

/* where the share list is kept: ENVARC:Lagoon/lagoon.conf (the Mac's MUI reads this as the
 * Lagoon folder in the Preferences folder) */
#define LM_CONF_DIR  "ENVARC:Lagoon"
#define LM_CONF_FILE "ENVARC:Lagoon/lagoon.conf"
#define LM_ENV_FILE  "ENV:Lagoon/lagoon.conf"

#endif
