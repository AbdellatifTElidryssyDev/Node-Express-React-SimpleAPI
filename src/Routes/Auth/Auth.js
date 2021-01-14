import { Router } from "express";
import authController from "../../Controller/Auth/Auth";

const router = Router();
const AuthCOntroller = new authController();

router.post("/api/user-signup", (request, response) => {
  AuthCOntroller.SignUp(request, response);
});
router.post("/api/user-signin", (request, response) => {
  AuthCOntroller.SignIn(request, response);
});

export default router;
