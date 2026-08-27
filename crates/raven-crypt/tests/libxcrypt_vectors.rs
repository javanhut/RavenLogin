//! Cross-check against libxcrypt.
//!
//! The unit tests in `sha512_crypt` cover the published vectors and the
//! boundaries the implementation is most likely to get wrong. This covers the
//! boring middle: forty password/salt pairs of assorted lengths, each hashed by
//! the system's own `crypt(3)` (libxcrypt, via perl) on the build host and
//! pasted in.
//!
//! The value is in the lengths. sha512-crypt's input schedule depends on the
//! *length* of the password in three separate places, so a transcription error
//! typically produces a hash that is correct for some lengths and wrong for
//! others. One vector proves almost nothing; forty spread across 1..130 bytes,
//! with salts of 1..16, is enough that a surviving bug would have to be very
//! strange.
//!
//! Regenerating these means running libxcrypt again, which is deliberate:
//! there is no point cross-checking against a table this crate produced.

use raven_crypt::{Verdict, sha512_crypt, verify};

/// `(password, setting, expected_hash)`, from `crypt(3)` on the build host.
#[rustfmt::skip]
const VECTORS: &[(&str, &str, &str)] = &[
    ("q7vfdEvjT", "$6$ny", "$6$ny$djI885PwhxY/0WCw5WxfhZbBc9j26sUDD4yBW9ZaSdc9zmyfxIgoBIU1MqBOueaFz/AeAy32kw2wQlD86OVw3."),
    ("lDT072gq1rbVM 09qG", "$6$3iTI4W6cR", "$6$3iTI4W6cR$IQKO1AH415mEL0ryX7lvGKf41ijIDxPyOCvJgBhtSxRKbJV4m72mSTtvDq3sVsJs0gqpDLIhoA8WSx.4RAGLM."),
    ("Gl7XFbTLgsK#ZH6fJbRjcIk/", "$6$VvTBy3gxk2Po", "$6$VvTBy3gxk2Po$NCuSzkaX9p2pSO2H7i6wYQSGCZ3x28orfFs/yCeFWWKzEv5.VvFu34aJ8584AVmeLPdrVh3eBfM9K5qgNP1Jz/"),
    ("1V4wL8dcex1Ehop/G9SEp8#xcOGKRLC3t", "$6$65jPzeY", "$6$65jPzeY$bFuoBkREmbQU7d0NL1YU7BGMxNJj24lzUmAw3C.LZ9i373QZ6Cm2z7ziVdmnZWCEAFzpcKFgYu1V5AWleChjp/"),
    ("8pgn/6CSOiJTe YDRf11aB/Ad1RcW RGU6f6Hsjg Z", "$6$DrwH2F0BT8", "$6$DrwH2F0BT8$eBuHzNFBSHHIWVhSowYDnKthRYZncM72xrbhZxEGkFYDsbj8tFHbjprkFtybDy4Cb5z1ZrBCt.BgQTSa3RoAS."),
    ("WeXNT.fDsUzTmfd.!AD#xOe02OqOc8143SGHJY!v4cS8ojyH", "$6$HSkc6zroEg", "$6$HSkc6zroEg$wMIO9UYweHFeD4whqHfKOv5fz.h8p3NJM/53EK0jGf4Ai8l5KABd3dJCqr3nFpdhwQwuLM4L8ufBwHCswKv/Y/"),
    ("csvNB02Y f59zr7iuo8RY7E6JR5X81I.6XrBbQ5om9uEQ08TR#.qgzI/h", "$6$IfRB6b3Hp", "$6$IfRB6b3Hp$3nNH6h2rURWID1l1rfH8U5YfdHjoj9LVeBgYzxnzenbornjDYLM/NPkUEXwIQ3fT7EuN95WOG2vO2UfE0vN2P1"),
    ("a3dFO6fNs3.grdB9vTLautQ9DzK6fpz0x/M#vBM0rVHiYNHb#4RmQIV1gx27uq2o6a", "$6$kfZPMu", "$6$kfZPMu$PJcwznwE1WfpoSaMUtAYe1o9OVZMMtKPZbhqFDDFPgNu8ZT07H8aiVkBkRK7i/rPMXq1jsQjztBZ4KLrAhl.Q/"),
    ("DhlMViL1TnK2sLzTW2YlktsaDWs0U!L9/XV13kD.DmtVOSJJYrHIL.slcF8zotlTIaqIcuppaiC9OolRXAHc1PUj2fLUrDXsnlOCRAKCjf.k", "$6$6yrNtt", "$6$6yrNtt$PcsoKIDiTAi1xxUTbmJ496Rjtu2i6TYzZ9eo4aZl47HbBCTWvZfOa0LQWBXM4jHUfFd.v8wh05/IxY1e2HDT9/"),
    ("tdFnlGjvXCts6Cst6k9ujoF2 1pPCfDvy.pXf k4LJLjPX4RxJEQYg9Q0i1VBEcGJoOYyY!6GCtkgw#i3.Poz9#AvZvVoBRynxhXP6EoYyJi", "$6$mDmZwQUW", "$6$mDmZwQUW$enjWlx0lhTww9kZ6jbOHV72EnSGsyyUUTFWl9Ecz6ZQ2yszNLt95iWviCyWLzOhsKh0GUNfP/zcv3abz2TTfw/"),
    ("GLDU5Pfhq1g 7DFApBG#G3K29yZlS17Qo49AyED/7ktX5fv6po7vIq", "$6$qdC5RsbelNTYU9c", "$6$qdC5RsbelNTYU9c$Hnegn1NkCYgotdjZyI1Z5aYwXL6qbstI9GhkeAWjnHgKz7RQnGYx4LvuD1fBucWEAA8IepQ4AOSD9JZIG4iB4."),
    ("1qR#K7ALp.RguLRUoDa7U5Lj33DgzJO8GAFZ3ros3/#bMSwvi m9mSWhpRPPTBeEDbCSrm9rdljXYhxONkIt 7fLHVRGOHuUHfn", "$6$QJNhW4", "$6$QJNhW4$wrrz2PbNUMuf1dlXS.iqNjIB7RpzB0StXbrZSFNEDCA78TwnujNMJYhXyQ1QiLl8V5kPmNC4uMD586LK4FSjm."),
    ("Y!GVkZScdc5HH7HZXiDnz!Lmr2mNytsbb CZTqD4OGbHF", "$6$X6D", "$6$X6D$T5IL9XpapOirqOd4/MIzRaKn7G2T9oS6JNxrtmU00tHB7SJQk9ssSNJlK5pyFmeibhHwD4aSi4yygZ6c910zQ1"),
    ("hyr4.aaRrtMqqQ0ptaurxug.7yF/EfKMr#BkXBChqG", "$6$RYrd", "$6$RYrd$hlUWjlqB5fnhd82u2mw6VUG/lXJAMOyJMK.cmYQzgRupekI5VB6XYjiVUjtGZRwYLOzxjAkFyENDbnjhPPpVO1"),
    ("F/WU", "$6$r", "$6$r$.pasF4ulCtBGlsHEfT.1N8Pkz39NoCVrbqmOlyrw/MOctXpVVKeNKyHJW3EpEUCzAMBdeK1FalJMQWGkW1Vnu/"),
    ("V#xs#!!g5g6ZRRi!Bimw!K4/mWFSi#OHzVF06DgKMbrmMZ8gn!PlgK57.gylYzFI/iQ1NplCCpdROIJL676yFLayGZpuwNceyRr1Mq", "$6$e", "$6$e$0p.oFvKbydIyveRMw71p7mGvAY26HpYt9Fip06XkcNntzkWXErgHACQv02KmMXPFg/1m7FKspCgw0hG9Do8xQ."),
    ("QT8fNiWC6ZpFYEKFQIM/FkqX1jdYXdjPLwBvNsqig5OWN74E0cW4#eb3M 597fCuXbTrVPQ lFz4ae6dOPCh8vtti!gal Wl", "$6$eVWfdgi1Rm0", "$6$eVWfdgi1Rm0$iLseLnTIyRNhNaZVutIsHJrOdYj7n6E05S/dr.kc/gW5IAItH2ENRR/rkWWHLKQcobS8ouFa5O7tXtfR2nrMA."),
    ("PPm8klzrXxpbt1KsPid1Uyvk0TI.", "$6$mfCud6bPUhuC", "$6$mfCud6bPUhuC$fz4cVYdLaXVilCWS/dC/l0uHBSPRTc6th5nW7PZHvWBoa7yyNmVBlbnxbZC3Jd1h4CoubfFtrc/XJC4YhuJEO0"),
    ("wZCohfk6gzG918tgpV/p0Z8s.VGrA gzH6xW8#k/#TyAj31opz/5esqPl#csbGeLdo/wrzPAo Tgh2ZC!oYa70u6Uca.xa4Qpc3eGEn/Do#dK! i#L Oo.BwGTok", "$6$ukGLDgJUBgju", "$6$ukGLDgJUBgju$rAqjep1LCI7KuF2zz5mHf8wsdCc0OqUxcCh34TtVktLkezu1LLhXzDi347PrTGIpsj2B87Zvkr1qJJsr6BKEL1"),
    ("RG rH", "$6$HRMPA", "$6$HRMPA$Zet5mHQFDsV.5xBj5WHJnPIdbxKVT63OMO52/a/av62JYuMVkmWIuIXjIErsKqsmp3hqhJwHNfttBSEGeD/KY0"),
    ("aGjlEJqKr/ ", "$6$IC3DsC8", "$6$IC3DsC8$UyOkSPdcQqviqLDZzr67IY0wvMwOqqNMsEaM6ePi./.yvmAt9vpmvr7ohW9HXhHUfgzE.ijmz2CvXk08NM.h5."),
    ("c8 /ey0eUt8bekdJDJZld369B9lzWwYMino#fbGfzd03P0TnknwkzY.4TCD/sQ.W6FmsmIFtiVBxHhDeuOhBPJR.GZzRarLC5UPPM9VpIqjU", "$6$wbYN", "$6$wbYN$cTKz2l5NfBUJ6JcQ4lpb8hJlsD3/aO.V1WQI4bhmssUZgmQfimTd1pcZiqMcDO8katjAS45Rxrl2Q/RvOM9HO1"),
    ("mADW.sM4DHzIrqQpG5TUZQnSAK/YcZhxIm7", "$6$BsqUbGkoeo", "$6$BsqUbGkoeo$lJt56ls4Aaqyu8awJRAGRXb386qzdcI9Vj7GCcv8YUhajIm2WhfT19U77GN.WMBJuGLHK26VA5MIg.02JlbUB."),
    ("q#HS", "$6$rmlsXyEBo", "$6$rmlsXyEBo$ioWGc/PcWp21E1NNmNAssA11I4qtqCu3gKakff16/YcVRyakhYohqMyEqCEeXRPVXsZKqZpokHe9vsXeSLEh0."),
    ("hM8AHMF9iwr30X1ScZ5LzZBnPrr6q. Oz!7GduSEH8i2t 7EX5U/#6GXBfthVQQK7PP7BmjNJB!#dR3fWrU iXOO4NXJF77YTWMM.EJ.4dt/aV", "$6$ehEsuG", "$6$ehEsuG$I4ryuZGzdMhjrL8XQ6oBCbMl3fSWL9Yqi0lrS4n7siMWBQ0oOAxn2EnYQUbbCljYhZ4m4RPxWlelMSAS1smID."),
    ("A4hfZPJu0AK#vA#7wjazZZU5pcPlIwFu2gtHZ/cLCSS1k5l8whKTXY0sgZRER2Oi!yRcau9maB G0VBkfbSo9O.D69Zkh#S.Q4", "$6$4VKL7", "$6$4VKL7$CBkl7Utieq3pTF/fDZnOna5zW4hN/w01p8GS0RGFIejnce.nvXaIMJDF5IphLagb5SiheFlqSlltf/wjqFcO6."),
    ("otYV96GqBhb9UxYH", "$6$y10UmQPD9", "$6$y10UmQPD9$qOZXW.9mELX48lG7xpmKl7TODpqlMvcvJ4RkD.wyWugxRaWs8u0SyEzlYAwv58uMvhGSmq.aD2/xerYIGAovi."),
    ("Rb jWHwq7J6woaVLiTMGoTpx1V73fQ6Ce4u3vvC.b5xzzWe Bq.C!RRKPfhIZH#yoREK8b6 fJL1Zu8cdru2z2sWdOZHaQRzwgcb/PKpA.oXy", "$6$iI", "$6$iI$Z0uagBxg.isPduVIWY.NV2jjiWkttbCWW2vTCRDyTpaotFRbMv7ZDRHOtX6.CZYyokO0cWyyj.KaKylrUynjI0"),
    ("8IivxViRsER4p##8bZ4rkRrlF3tS0n0gxd!nE/5tdfs1IjpQu I/J5gCtPYgTivWAD.1yLi0NT0Y3T2I7#KLM0svVKFLIZqCK1IX8U5/eXwA4tEANgdXEK4jj511T2", "$6$yTlo8PLvGJW", "$6$yTlo8PLvGJW$dI/E1NaLPKrIZuYirHIqZOZL20LYL5bxuqaPrQWmitSAwEtG5apcZCSsju339L/ybFvBbn4JZ1NvHwcNPM/i50"),
    ("OiJaUnyzpu6Ow541bOfosiBB9tBK3", "$6$RdUBLWQMmdort", "$6$RdUBLWQMmdort$8kMY.xFu1fUt3Z4xQZyIuwEfv.B7QT2d/nJrUmNHIwzVJlD4DHToNx8MUpLqCxMm1rEiIdrIhru65ITh9Ltlf/"),
    ("Deh.pcCG!pWMaz!PSVAN!HEeD070u5OBf", "$6$0aL", "$6$0aL$Nx73.P2nDJsL1q7pd.D/tz4wYp0DXv2lUhZH/JrCcPYDXQEOWn1SElQfUaDsvOsqBoxZSRW7w2fzYi9kqifEa0"),
    ("ClJF//IJM9O9o/1jfwES8Fjs 0TLLOt.jO2 uQ1aCeHT8dCq g2#mJEOW3y#RDdWMXEMeJpF07WL!yoiOJgnkyV3.QN.QPVWtXCELpjIwnti2xzvLm55W", "$6$Pxxg", "$6$Pxxg$UbQZwEu3XZarKQz1dY4ErcNVhLntrN4a/48b0fcUr16A5B3iqyChDYx74XlILPHVhihS/SKTSWV9DNj8XNo37/"),
    ("MkTjJUMXcViqBGlEQUvweue2FdqT.c!yvLwikElgeeH838UlHPJpywr/yjYFEq9DEvu5NOv2gjP2", "$6$S1FiXIn1Wy5wzb8", "$6$S1FiXIn1Wy5wzb8$OxdV/6NafAGsDFetbjkE23y/XlLnBFJ7fCtH.FsEnerYWJgqHIlCkIgcrMPA9d2VLDjXNR9XMPCYYU/iVt2aJ0"),
    ("ucgfmlAUZrMbG1Gc8rQALkQ55 i 7oPJ6RKguetLh#B#bPo1jk6ne7btvZNGLa.UQQywbuapCsWG9#5.g2tatIfRt. Ekgzr5RfXY1Lc2", "$6$AsN8A8ubGqC", "$6$AsN8A8ubGqC$.ReBVSFrKLCJ6wSZXi17xqT0e8Ca70uodRcofmwvjsg7UlPLeiFKeyKP/SryZiVIWCA2yiWTdV0uKTEbzQmoC0"),
    ("w9e5qdfVlX9ul2HO/cOQF0Dj971YYTWU3P1uC a!vYAEC8v#0n.lwAqwqRAjG9jyJROggfx6CApJ#/N6V2Bo 9.ya7XM76jv", "$6$2Tfzl", "$6$2Tfzl$GsaN0tV9jaGi0MXwtfWWi9pGsWX0S5warDr6iWi6t72RPzoIeQh7Xdz8oqqcKCr5QAncp2AJlENmATf94JBnb0"),
    ("iPLyfMapSiEMD2tSeGDv8SlhrWVSEue8Qi5E", "$6$nqlIwImsk9pm", "$6$nqlIwImsk9pm$LSlYMEWGk8ga/wD2VehbWJcY6MHzkSS62SAF2x1jFnrHCl4oQ5TgEs7NSLFR70QaTGwuD8zXwQGSqKZCI0vZN."),
    ("3hTlvJjyoCYdAM!!UesYBrAvKjF8t4LDWqFy8nT!BZMao3BsQ#H O!AaBLWNJsV j!AJwqok#PqVvG2Vib4iP9Zl6cdJaN.sbF#J0HK8rAJn53sNI2ZCUiAUhkz", "$6$eh9OqHYygJXe", "$6$eh9OqHYygJXe$maByo//A/vX3lmpToSomuK9PI/IqRw6g1gWkM.TFSELhZivQ6odObMZ32lEYOfy8/3cWzS2HBicVwZPDodqMA0"),
    ("GXTiCQgvps4R45N/LsADXZc17bC5I8WxMfYhAHe7Z4RHDdwQ2zgH42wmBqQ3cv8MDTOpPCcmIRq6FjSqkSpn", "$6$6Jrl4Wa9E", "$6$6Jrl4Wa9E$Pna/szEn0jzvcdTSovLyzrA7D/uRp4ZsgMn1q5sSabB0DGwzxUqReg8ht90ZmC5vk54OCj.0QuL/7v7EVwTFx/"),
    ("4N784CAYmgOH8", "$6$u28urtf", "$6$u28urtf$ndg5myFPMeVN1DoQcnWU7Kz7QUxajg0XMga29./WXoegAF6yskhC0l1AkELcz3biA4iZlipZBZuVDG.XCkztK/"),
    ("y", "$6$223jVnCw5UyiO9rI", "$6$223jVnCw5UyiO9rI$KbZ4DkgN5oej.ngLrgHCHTif2CUMPnVcOs4WCz4jE6ApqvTFryPnoLhw05fvWlbxfRGv8aaDIGIATAermi2Ss1"),
];

#[test]
fn matches_libxcrypt_on_every_vector() {
    for (password, setting, expected) in VECTORS {
        let got = sha512_crypt(password.as_bytes(), setting).expect("a valid $6$ setting");
        assert_eq!(
            &got,
            expected,
            "\n  password ({} bytes): {password:?}\n  setting: {setting}",
            password.len()
        );
    }
}

#[test]
fn verifies_every_vector() {
    for (password, _, expected) in VECTORS {
        assert_eq!(
            verify(password.as_bytes(), expected),
            Verdict::Match,
            "password {password:?} should verify against its own hash"
        );
    }
}

/// Every password must fail against the *next* vector's hash. A broken
/// implementation that returned a constant, or that ignored the password
/// entirely, would still pass the two tests above; it cannot pass this one.
///
/// Pairwise rather than the full cross product on purpose: sha512-crypt is
/// 5000 SHA-512 compressions per call, so all 1560 combinations cost minutes
/// of test time to prove the same thing this proves in seconds.
#[test]
fn no_password_verifies_against_the_next_vectors_hash() {
    for (i, (password, _, _)) in VECTORS.iter().enumerate() {
        let (_, _, other) = VECTORS[(i + 1) % VECTORS.len()];
        assert_eq!(
            verify(password.as_bytes(), other),
            Verdict::Mismatch,
            "vector {i}'s password matched the next vector's hash"
        );
    }
}
